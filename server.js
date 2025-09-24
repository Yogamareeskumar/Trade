const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const Joi = require('joi');
const math = require('mathjs');
const ss = require('simple-statistics');
const validator = require('validator');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false, // Disable for API
  crossOriginEmbedderPolicy: false
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'production' ? 100 : 1000,
  message: {
    error: 'Too many requests from this IP, please try again later.'
  }
});
app.use('/api/', limiter);

// Production logging
if (process.env.NODE_ENV === 'production') {
  const originalLog = console.log;
  console.log = (...args) => {
    const timestamp = new Date().toISOString();
    originalLog(`[${timestamp}]`, ...args);
  };
}

// Supabase configuration - Use environment variables
const supabaseUrl = process.env.SUPABASE_URL || 'https://fsicauceosmdrhxmvreu.supabase.co';
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZzaWNhdWNlb3NtZHJoeG12cmV1Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1ODEwMjk5OSwiZXhwIjoyMDczNjc4OTk5fQ.bqzxqGvx_l8-PQ4Ms5fgorweqQCn8fWaBF1O8fs8lX0';
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZzaWNhdWNlb3NtZHJoeG12cmV1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTgxMDI5OTksImV4cCI6MjA3MzY3ODk5OX0.J_Dx9SLkzffTFcDhxMix56cmtpM4710nqafnyP5BLhk';

// Validate required environment variables
if (!supabaseUrl || !supabaseServiceKey || !supabaseAnonKey) {
  console.error('❌ FATAL ERROR: Supabase configuration is required!');
  console.error('Please configure SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, and SUPABASE_ANON_KEY');
  process.exit(1);
}

// Initialize Supabase clients
let supabaseAdmin = null;
let supabase = null;
let createClient = null;

try {
  const supabaseJs = require('@supabase/supabase-js');
  createClient = supabaseJs.createClient;
  
  supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    },
    db: { schema: 'public' }
  });
  
  supabase = createClient(supabaseUrl, supabaseAnonKey, {
    db: { schema: 'public' }
  });
  
  console.log('✅ Supabase clients initialized successfully');
} catch (error) {
  console.error('❌ FATAL ERROR: Failed to initialize Supabase:', error.message);
  process.exit(1);
}

// PostgreSQL connection pool
const pool = new Pool({
  host: process.env.DB_HOST || 'db.fsicauceosmdrhxmvreu.supabase.co',
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || '3146',
  database: process.env.DB_NAME || 'postgres',
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
  ssl: {
    rejectUnauthorized: false
  }
});

pool.on('connect', () => {
  console.log('✅ Connected to PostgreSQL database');
});

pool.on('error', (err) => {
  console.error('❌ PostgreSQL connection error:', err);
});

// CORS configuration for production
const allowedOrigins = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  process.env.FRONTEND_URL,
  process.env.CUSTOM_DOMAIN,
  // Add your production URLs here
].filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1 || process.env.NODE_ENV !== 'production') {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Validation schemas
const userProfileSchema = Joi.object({
  phone: Joi.string().pattern(/^[0-9]{10}$/).optional(),
  tradingExperience: Joi.string().valid('beginner', 'intermediate', 'advanced', 'professional').optional(),
  preferredMarket: Joi.string().optional(),
  riskTolerance: Joi.string().valid('low', 'medium', 'high').optional()
});

const tradeSchema = Joi.object({
  status: Joi.string().valid('open', 'closed').required(),
  broker: Joi.string().required(),
  market: Joi.string().required(),
  instrument: Joi.string().required(),
  direction: Joi.string().valid('buy', 'sell').required(),
  qty: Joi.number().positive().required(),
  entry_price: Joi.number().positive().required(),
  exit_price: Joi.number().positive().optional(),
  entry_dt: Joi.date().iso().required(),
  exit_dt: Joi.date().iso().optional(),
  stoploss: Joi.number().positive().required(),
  commission: Joi.number().min(0).required(),
  p_and_l: Joi.number().optional(),
  strategy: Joi.string().required(),
  setup: Joi.string().optional(),
  reason: Joi.string().optional()
});

// Helper functions
const safeParseFloat = (value) => {
  if (value === null || value === undefined) return null;
  if (typeof value === 'number') return value;
  if (typeof value === 'string') {
    const parsed = parseFloat(value);
    return isNaN(parsed) ? null : parsed;
  }
  return null;
};

const formatTradeData = (trade) => {
  if (!trade) return null;
  return {
    ...trade,
    s_no: parseInt(trade.s_no) || trade.s_no,
    qty: safeParseFloat(trade.qty),
    entry_price: safeParseFloat(trade.entry_price),
    exit_price: safeParseFloat(trade.exit_price),
    stoploss: safeParseFloat(trade.stoploss),
    commission: safeParseFloat(trade.commission),
    p_and_l: safeParseFloat(trade.p_and_l),
    entry_dt: trade.entry_dt,
    exit_dt: trade.exit_dt,
    created_at: trade.created_at,
    updated_at: trade.updated_at
  };
};

const formatTradesData = (trades) => {
  if (!trades || !Array.isArray(trades)) return [];
  return trades.map(formatTradeData);
};

// Authentication middleware
const authenticateSupabaseUser = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
      return res.status(401).json({ 
        error: 'Authentication required',
        message: 'Authorization header is missing' 
      });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      return res.status(401).json({ 
        error: 'Authentication required',
        message: 'Bearer token is missing' 
      });
    }

    const { data: { user }, error } = await supabaseAdmin.auth.getUser(token);

    if (error) {
      console.error('Token verification error:', error);
      return res.status(403).json({ 
        error: 'Authentication failed',
        message: 'Invalid or expired token' 
      });
    }

    if (!user) {
      return res.status(403).json({ 
        error: 'Authentication failed',
        message: 'User not found' 
      });
    }

    const userSupabase = createClient(supabaseUrl, supabaseAnonKey, {
      global: {
        headers: {
          Authorization: `Bearer ${token}`
        }
      },
      db: { schema: 'public' }
    });

    req.user = {
      id: user.id,
      email: user.email,
      ...user.user_metadata
    };
    req.supabase = userSupabase;

    next();
  } catch (error) {
    console.error('Authentication middleware error:', error);
    return res.status(500).json({ 
      error: 'Authentication service error',
      message: 'Failed to verify authentication' 
    });
  }
};

// Database initialization
const initializeDatabase = async () => {
  try {
    console.log('🔧 Initializing database schema...');
    
    await pool.query('SELECT 1');
    console.log('✅ PostgreSQL connection verified');

    // Create user_profiles table
    const userProfilesTable = `
      CREATE TABLE IF NOT EXISTS user_profiles (
        user_id UUID PRIMARY KEY,
        phone VARCHAR(15),
        trading_experience VARCHAR(20) CHECK (trading_experience IN ('beginner', 'intermediate', 'advanced', 'professional')) DEFAULT 'beginner',
        preferred_market VARCHAR(100),
        risk_tolerance VARCHAR(10) CHECK (risk_tolerance IN ('low', 'medium', 'high')) DEFAULT 'medium',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `;

    await pool.query(userProfilesTable);
    console.log('✅ User profiles table created/verified');

    // Create trading_journal table
    const tradingJournalTable = `
      CREATE TABLE IF NOT EXISTS trading_journal (
        s_no SERIAL PRIMARY KEY,
        user_id UUID NOT NULL,
        status VARCHAR(10) CHECK (status IN ('open', 'closed')) NOT NULL,
        broker VARCHAR(100) NOT NULL,
        market VARCHAR(100) NOT NULL,
        instrument VARCHAR(100) NOT NULL,
        direction VARCHAR(10) CHECK (direction IN ('buy', 'sell')) NOT NULL,
        qty DECIMAL(15,4) NOT NULL,
        entry_price DECIMAL(15,4) NOT NULL,
        exit_price DECIMAL(15,4),
        entry_dt TIMESTAMP NOT NULL,
        exit_dt TIMESTAMP,
        stoploss DECIMAL(15,4) NOT NULL,
        commission DECIMAL(15,4) NOT NULL,
        p_and_l DECIMAL(15,4),
        strategy VARCHAR(100) NOT NULL,
        setup TEXT,
        reason TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `;

    await pool.query(tradingJournalTable);
    console.log('✅ Trading journal table created/verified');

    // Create indexes
    await pool.query('CREATE INDEX IF NOT EXISTS idx_user_profiles_user_id ON user_profiles(user_id);');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_trading_journal_user_id ON trading_journal(user_id);');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_trading_journal_status ON trading_journal(status);');
    console.log('✅ Database indexes created');

    console.log('✅ Database initialization completed successfully');
  } catch (error) {
    console.error('❌ Database initialization error:', error);
    throw error;
  }
};

// Routes
app.get('/', (req, res) => {
  res.json({ 
    message: 'TradingJournal Pro API', 
    version: '1.0.0',
    status: 'running',
    timestamp: new Date().toISOString()
  });
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Trading Journal API is running with Supabase Auth + RLS!',
    authMode: 'Supabase Authentication + Row Level Security',
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString()
  });
});

app.get('/api/db-status', async (req, res) => {
  try {
    const pgResult = await pool.query('SELECT NOW() as current_time, version() as pg_version');
    const { data, error } = await supabaseAdmin.auth.admin.listUsers({ page: 1, perPage: 1 });

    res.json({ 
      connected: true, 
      message: 'Database connected successfully',
      authMode: 'Supabase Authentication + Row Level Security',
      postgresConnected: true,
      supabaseConnected: !error,
      dbTime: pgResult.rows[0].current_time,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Database status check failed:', error);
    res.status(500).json({ 
      connected: false, 
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// User profile routes
app.get('/api/auth/profile', authenticateSupabaseUser, async (req, res) => {
  try {
    const userId = req.user.id;
    
    let result = await pool.query(
      'SELECT * FROM user_profiles WHERE user_id = $1',
      [userId]
    );
    
    let profile;
    if (result.rows.length === 0) {
      const insertResult = await pool.query(
        'INSERT INTO user_profiles (user_id) VALUES ($1) RETURNING *',
        [userId]
      );
      profile = insertResult.rows[0];
    } else {
      profile = result.rows[0];
    }

    res.json({
      user: {
        id: req.user.id,
        email: req.user.email,
        firstName: req.user.first_name,
        lastName: req.user.last_name,
        phone: profile.phone,
        tradingExperience: profile.trading_experience,
        preferredMarket: profile.preferred_market,
        riskTolerance: profile.risk_tolerance,
        createdAt: profile.created_at,
        updatedAt: profile.updated_at
      }
    });
  } catch (error) {
    console.error('Error fetching profile:', error);
    res.status(500).json({ 
      error: 'Failed to fetch profile',
      message: error.message 
    });
  }
});

app.put('/api/auth/profile', authenticateSupabaseUser, async (req, res) => {
  try {
    const { error: validationError, value } = userProfileSchema.validate(req.body);
    if (validationError) {
      return res.status(400).json({
        error: 'Validation Error',
        details: validationError.details.map(detail => detail.message)
      });
    }

    const userId = req.user.id;
    const updateData = {
      ...value,
      updated_at: new Date().toISOString()
    };

    Object.keys(updateData).forEach(key => 
      updateData[key] === undefined && delete updateData[key]
    );
    
    const updateColumns = Object.keys(updateData);
    const setClause = updateColumns.map((col, index) => `${col} = $${index + 2}`).join(', ');
    const values = [userId, ...updateColumns.map(col => updateData[col])];
    
    const result = await pool.query(
      `UPDATE user_profiles SET ${setClause} WHERE user_id = $1 RETURNING *`,
      values
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    const profile = result.rows[0];

    res.json({
      message: 'Profile updated successfully',
      user: {
        id: req.user.id,
        email: req.user.email,
        phone: profile.phone,
        tradingExperience: profile.trading_experience,
        preferredMarket: profile.preferred_market,
        riskTolerance: profile.risk_tolerance,
        updatedAt: profile.updated_at
      }
    });
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ 
      error: 'Failed to update profile',
      message: error.message 
    });
  }
});

// Trading routes
app.get('/api/trades', authenticateSupabaseUser, async (req, res) => {
  try {
    const { status, strategy, limit = 1000 } = req.query;
    const userId = req.user.id;
    
    let pgQuery = 'SELECT * FROM trading_journal WHERE user_id = $1';
    const values = [userId];
    let paramCount = 1;

    if (status) {
      paramCount++;
      pgQuery += ` AND status = $${paramCount}`;
      values.push(status);
    }

    if (strategy) {
      paramCount++;
      pgQuery += ` AND strategy = $${paramCount}`;
      values.push(strategy);
    }

    pgQuery += ` ORDER BY s_no DESC LIMIT $${paramCount + 1}`;
    values.push(parseInt(limit));

    const result = await pool.query(pgQuery, values);
    const trades = result.rows;
    const formattedTrades = formatTradesData(trades || []);

    res.json({
      trades: formattedTrades,
      count: formattedTrades.length
    });
  } catch (error) {
    console.error('Error fetching trades:', error);
    res.status(500).json({ 
      error: 'Failed to fetch trades',
      message: error.message 
    });
  }
});

app.post('/api/trades', authenticateSupabaseUser, async (req, res) => {
  try {
    const { error: validationError, value } = tradeSchema.validate(req.body);
    if (validationError) {
      return res.status(400).json({
        error: 'Validation Error',
        details: validationError.details.map(detail => detail.message)
      });
    }

    const tradeData = {
      user_id: req.user.id,
      status: value.status,
      broker: value.broker,
      market: value.market,
      instrument: value.instrument,
      direction: value.direction,
      qty: value.qty,
      entry_price: value.entry_price,
      exit_price: value.exit_price || null,
      entry_dt: value.entry_dt,
      exit_dt: value.exit_dt || null,
      stoploss: value.stoploss,
      commission: value.commission,
      p_and_l: value.p_and_l || null,
      strategy: value.strategy,
      setup: value.setup || null,
      reason: value.reason || null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    const result = await pool.query(`
      INSERT INTO trading_journal (
        user_id, status, broker, market, instrument, direction,
        qty, entry_price, exit_price, entry_dt, exit_dt,
        stoploss, commission, p_and_l, strategy, setup, reason,
        created_at, updated_at
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
      ) RETURNING *
    `, [
      tradeData.user_id, tradeData.status, tradeData.broker, tradeData.market,
      tradeData.instrument, tradeData.direction, tradeData.qty, tradeData.entry_price,
      tradeData.exit_price, tradeData.entry_dt, tradeData.exit_dt, tradeData.stoploss,
      tradeData.commission, tradeData.p_and_l, tradeData.strategy, tradeData.setup,
      tradeData.reason, tradeData.created_at, tradeData.updated_at
    ]);

    const trade = result.rows[0];
    const formattedTrade = formatTradeData(trade);

    res.status(201).json({
      message: 'Trade created successfully',
      trade: formattedTrade
    });
  } catch (error) {
    console.error('Error creating trade:', error);
    res.status(500).json({ 
      error: 'Failed to create trade',
      message: error.message 
    });
  }
});

app.put('/api/trades/:id', authenticateSupabaseUser, async (req, res) => {
  try {
    const tradeId = req.params.id;
    const userId = req.user.id;
    
    const { error: validationError, value } = tradeSchema.validate(req.body);
    if (validationError) {
      return res.status(400).json({
        error: 'Validation Error',
        details: validationError.details.map(detail => detail.message)
      });
    }

    const updateData = {
      ...value,
      updated_at: new Date().toISOString()
    };

    const result = await pool.query(`
      UPDATE trading_journal SET
        status = $3, broker = $4, market = $5, instrument = $6, direction = $7,
        qty = $8, entry_price = $9, exit_price = $10, entry_dt = $11, exit_dt = $12,
        stoploss = $13, commission = $14, p_and_l = $15, strategy = $16,
        setup = $17, reason = $18, updated_at = $19
      WHERE s_no = $1 AND user_id = $2
      RETURNING *
    `, [
      tradeId, userId, updateData.status, updateData.broker, updateData.market,
      updateData.instrument, updateData.direction, updateData.qty, updateData.entry_price,
      updateData.exit_price, updateData.entry_dt, updateData.exit_dt, updateData.stoploss,
      updateData.commission, updateData.p_and_l, updateData.strategy, updateData.setup,
      updateData.reason, updateData.updated_at
    ]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Trade not found or unauthorized' });
    }
    const trade = result.rows[0];
    const formattedTrade = formatTradeData(trade);

    res.json({
      message: 'Trade updated successfully',
      trade: formattedTrade
    });
  } catch (error) {
    console.error('Error updating trade:', error);
    res.status(500).json({ 
      error: 'Failed to update trade',
      message: error.message 
    });
  }
});

app.delete('/api/trades/:id', authenticateSupabaseUser, async (req, res) => {
  try {
    const tradeId = req.params.id;
    const userId = req.user.id;

    const result = await pool.query(
      'DELETE FROM trading_journal WHERE s_no = $1 AND user_id = $2 RETURNING s_no',
      [tradeId, userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Trade not found or unauthorized' });
    }
    const trade = result.rows[0];

    res.json({
      message: 'Trade deleted successfully',
      tradeId: trade.s_no
    });
  } catch (error) {
    console.error('Error deleting trade:', error);
    res.status(500).json({ 
      error: 'Failed to delete trade',
      message: error.message 
    });
  }
});

// Analytics routes
app.get('/api/analytics/stats', authenticateSupabaseUser, async (req, res) => {
  try {
    const userId = req.user.id;

    const result = await pool.query(
      'SELECT status, p_and_l FROM trading_journal WHERE user_id = $1',
      [userId]
    );
    const trades = result.rows;

    const totalTrades = trades.length;
    const openTrades = trades.filter(t => t.status === 'open').length;
    const closedTrades = trades.filter(t => t.status === 'closed').length;
    
    const pnlValues = trades
      .filter(t => t.p_and_l !== null && t.p_and_l !== undefined)
      .map(t => safeParseFloat(t.p_and_l))
      .filter(val => val !== null);
    
    const totalPnl = pnlValues.reduce((sum, val) => sum + val, 0);
    const avgPnl = pnlValues.length > 0 ? totalPnl / pnlValues.length : 0;
    const winningTrades = pnlValues.filter(val => val > 0).length;
    const losingTrades = pnlValues.filter(val => val < 0).length;
    const bestTrade = pnlValues.length > 0 ? Math.max(...pnlValues) : 0;
    const worstTrade = pnlValues.length > 0 ? Math.min(...pnlValues) : 0;
    const winRate = closedTrades > 0 ? (winningTrades / closedTrades) * 100 : 0;

    res.json({
      total_trades: totalTrades,
      open_trades: openTrades,
      closed_trades: closedTrades,
      winning_trades: winningTrades,
      losing_trades: losingTrades,
      total_pnl: parseFloat(totalPnl.toFixed(2)),
      avg_pnl: parseFloat(avgPnl.toFixed(2)),
      best_trade: parseFloat(bestTrade.toFixed(2)),
      worst_trade: parseFloat(worstTrade.toFixed(2)),
      win_rate: parseFloat(winRate.toFixed(2))
    });
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ 
      error: 'Failed to fetch statistics',
      message: error.message 
    });
  }
});

// Advanced analytics routes (simplified for production)
app.get('/api/analytics/advanced-stats', authenticateSupabaseUser, async (req, res) => {
  try {
    const userId = req.user.id;
    const result = await pool.query(
      'SELECT * FROM trading_journal WHERE user_id = $1 ORDER BY entry_dt',
      [userId]
    );
    const trades = result.rows;

    if (!trades || trades.length === 0) {
      return res.json({
        stats: {
          basic: {
            totalTrades: 0, closedTrades: 0, openTrades: 0, totalPnL: 0,
            avgPnL: 0, winRate: 0, profitFactor: 0, expectancy: 0
          },
          risk: {
            sharpeRatio: 0, maxDrawdown: 0, calmarRatio: 0,
            var95: 0, var99: 0, volatility: 0
          },
          performance: {
            avgWin: 0, avgLoss: 0, largestWin: 0, largestLoss: 0,
            riskRewardRatio: 0, kellyPercentage: 0, annualReturn: 0
          },
          time: {
            firstTradeDate: null, lastTradeDate: null,
            tradingDays: 0, avgTradesPerMonth: 0
          }
        }
      });
    }

    const formattedTrades = formatTradesData(trades);
    const closedTrades = formattedTrades.filter(t => t.status === 'closed' && t.p_and_l !== null);
    
    // Calculate basic stats
    const pnlValues = closedTrades.map(t => t.p_and_l).filter(p => p !== null);
    const totalPnL = pnlValues.reduce((sum, p) => sum + p, 0);
    const avgPnL = pnlValues.length > 0 ? totalPnL / pnlValues.length : 0;
    
    const winningTrades = pnlValues.filter(p => p > 0);
    const losingTrades = pnlValues.filter(p => p < 0);
    const winRate = pnlValues.length > 0 ? (winningTrades.length / pnlValues.length) * 100 : 0;
    
    const grossProfit = winningTrades.reduce((sum, p) => sum + p, 0);
    const grossLoss = Math.abs(losingTrades.reduce((sum, p) => sum + p, 0));
    const profitFactor = grossLoss > 0 ? grossProfit / grossLoss : (grossProfit > 0 ? 10 : 0);
    
    const avgWin = winningTrades.length > 0 ? grossProfit / winningTrades.length : 0;
    const avgLoss = losingTrades.length > 0 ? grossLoss / losingTrades.length : 0;
    
    // Risk metrics
    const volatility = pnlValues.length > 1 ? ss.standardDeviation(pnlValues) : 0;
    const sharpeRatio = volatility > 0 ? avgPnL / volatility : 0;
    
    // Time calculations
    const sortedTrades = closedTrades.sort((a, b) => new Date(a.entry_dt).getTime() - new Date(b.entry_dt).getTime());
    const firstTradeDate = sortedTrades[0]?.entry_dt;
    const lastTradeDate = sortedTrades[sortedTrades.length - 1]?.entry_dt;
    
    let tradingDays = 0;
    if (firstTradeDate && lastTradeDate) {
      const daysDiff = (new Date(lastTradeDate).getTime() - new Date(firstTradeDate).getTime()) / (1000 * 60 * 60 * 24);
      tradingDays = Math.max(daysDiff, 1);
    }

    const stats = {
      basic: {
        totalTrades: formattedTrades.length,
        closedTrades: closedTrades.length,
        openTrades: formattedTrades.length - closedTrades.length,
        totalPnL: parseFloat(totalPnL.toFixed(2)),
        avgPnL: parseFloat(avgPnL.toFixed(2)),
        winRate: parseFloat(winRate.toFixed(2)),
        profitFactor: parseFloat(profitFactor.toFixed(2)),
        expectancy: parseFloat(avgPnL.toFixed(2))
      },
      risk: {
        sharpeRatio: parseFloat(sharpeRatio.toFixed(2)),
        maxDrawdown: 0,
        calmarRatio: 0,
        var95: 0,
        var99: 0,
        volatility: parseFloat((volatility / Math.max(avgPnL, 1)).toFixed(4))
      },
      performance: {
        avgWin: parseFloat(avgWin.toFixed(2)),
        avgLoss: parseFloat(avgLoss.toFixed(2)),
        largestWin: pnlValues.length > 0 ? parseFloat(Math.max(...pnlValues).toFixed(2)) : 0,
        largestLoss: pnlValues.length > 0 ? parseFloat(Math.min(...pnlValues).toFixed(2)) : 0,
        riskRewardRatio: avgLoss > 0 ? parseFloat((avgWin / avgLoss).toFixed(2)) : 0,
        kellyPercentage: 0,
        annualReturn: 0
      },
      time: {
        firstTradeDate: firstTradeDate || null,
        lastTradeDate: lastTradeDate || null,
        tradingDays: Math.floor(tradingDays),
        avgTradesPerMonth: tradingDays > 30 ? parseFloat((closedTrades.length / (tradingDays / 30)).toFixed(2)) : closedTrades.length
      }
    };

    res.json({ stats });
  } catch (error) {
    console.error('Error fetching advanced stats:', error);
    res.status(500).json({ 
      error: 'Failed to fetch advanced statistics',
      message: error.message 
    });
  }
});

// Additional analytics endpoints
app.get('/api/analytics/time-series', authenticateSupabaseUser, async (req, res) => {
  try {
    const userId = req.user.id;
    const { period = 'daily' } = req.query;

    const result = await pool.query(
      'SELECT * FROM trading_journal WHERE user_id = $1 ORDER BY entry_dt',
      [userId]
    );
    const trades = result.rows;

    if (!trades || trades.length === 0) {
      return res.json({ data: [] });
    }

    const formattedTrades = formatTradesData(trades);
    const timeSeriesData = [];
    const groupedTrades = {};
    
    formattedTrades.forEach(trade => {
      const date = new Date(trade.entry_dt);
      let periodKey;
      
      switch (period) {
        case 'weekly':
          const weekStart = new Date(date);
          weekStart.setDate(date.getDate() - date.getDay());
          periodKey = weekStart.toISOString().slice(0, 10);
          break;
        case 'monthly':
          periodKey = date.toISOString().slice(0, 7);
          break;
        default:
          periodKey = date.toISOString().slice(0, 10);
      }
      
      if (!groupedTrades[periodKey]) {
        groupedTrades[periodKey] = {
          period: periodKey,
          trades: 0,
          totalPnL: 0,
          wins: 0,
          losses: 0,
          volume: 0
        };
      }
      
      const group = groupedTrades[periodKey];
      group.trades += 1;
      group.volume += trade.qty * trade.entry_price;
      
      if (trade.p_and_l !== null) {
        group.totalPnL += trade.p_and_l;
        if (trade.p_and_l > 0) group.wins += 1;
        if (trade.p_and_l < 0) group.losses += 1;
      }
    });
    
    let cumulativePnL = 0;
    Object.keys(groupedTrades)
      .sort()
      .forEach(periodKey => {
        const group = groupedTrades[periodKey];
        cumulativePnL += group.totalPnL;
        
        timeSeriesData.push({
          period: group.period,
          trades: group.trades,
          totalPnL: parseFloat(group.totalPnL.toFixed(2)),
          wins: group.wins,
          losses: group.losses,
          volume: parseFloat(group.volume.toFixed(2)),
          cumulativePnL: parseFloat(cumulativePnL.toFixed(2)),
          winRate: group.trades > 0 ? parseFloat(((group.wins / group.trades) * 100).toFixed(2)) : 0,
          avgPnL: group.trades > 0 ? parseFloat((group.totalPnL / group.trades).toFixed(2)) : 0
        });
      });

    res.json({ data: timeSeriesData });
  } catch (error) {
    console.error('Error fetching time series data:', error);
    res.status(500).json({ 
      error: 'Failed to fetch time series data',
      message: error.message 
    });
  }
});

app.get('/api/analytics/patterns', authenticateSupabaseUser, async (req, res) => {
  try {
    const userId = req.user.id;

    const result = await pool.query(
      'SELECT * FROM trading_journal WHERE user_id = $1 ORDER BY entry_dt',
      [userId]
    );
    const trades = result.rows;

    if (!trades || trades.length === 0) {
      return res.json({
        patterns: {
          bestWinStreak: 0,
          worstLossStreak: 0,
          dayOfWeekPerformance: {},
          instrumentPerformance: {}
        }
      });
    }

    const formattedTrades = formatTradesData(trades);
    const closedTrades = formattedTrades.filter(t => t.status === 'closed' && t.p_and_l !== null);

    // Calculate streaks
    let currentStreak = 0;
    let bestWinStreak = 0;
    let worstLossStreak = 0;
    let currentLossStreak = 0;

    closedTrades.forEach(trade => {
      if (trade.p_and_l > 0) {
        currentStreak += 1;
        currentLossStreak = 0;
        bestWinStreak = Math.max(bestWinStreak, currentStreak);
      } else if (trade.p_and_l < 0) {
        currentStreak = 0;
        currentLossStreak += 1;
        worstLossStreak = Math.max(worstLossStreak, currentLossStreak);
      }
    });

    // Day of week analysis
    const dayOfWeekPerformance = {};
    const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

    closedTrades.forEach(trade => {
      const dayIndex = new Date(trade.entry_dt).getDay();
      const dayName = dayNames[dayIndex];
      
      if (!dayOfWeekPerformance[dayName]) {
        dayOfWeekPerformance[dayName] = {
          trades: 0,
          totalPnL: 0,
          wins: 0
        };
      }
      
      dayOfWeekPerformance[dayName].trades += 1;
      dayOfWeekPerformance[dayName].totalPnL += trade.p_and_l;
      if (trade.p_and_l > 0) dayOfWeekPerformance[dayName].wins += 1;
    });

    Object.keys(dayOfWeekPerformance).forEach(day => {
      const data = dayOfWeekPerformance[day];
      data.winRate = data.trades > 0 ? (data.wins / data.trades) * 100 : 0;
      data.totalPnL = parseFloat(data.totalPnL.toFixed(2));
      data.winRate = parseFloat(data.winRate.toFixed(2));
    });

    // Instrument performance analysis
    const instrumentPerformance = {};

    closedTrades.forEach(trade => {
      if (!instrumentPerformance[trade.instrument]) {
        instrumentPerformance[trade.instrument] = {
          trades: 0,
          totalPnL: 0,
          wins: 0
        };
      }
      
      instrumentPerformance[trade.instrument].trades += 1;
      instrumentPerformance[trade.instrument].totalPnL += trade.p_and_l;
      if (trade.p_and_l > 0) instrumentPerformance[trade.instrument].wins += 1;
    });

    Object.keys(instrumentPerformance).forEach(instrument => {
      const data = instrumentPerformance[instrument];
      data.winRate = data.trades > 0 ? (data.wins / data.trades) * 100 : 0;
      data.avgPnL = data.trades > 0 ? data.totalPnL / data.trades : 0;
      data.totalPnL = parseFloat(data.totalPnL.toFixed(2));
      data.winRate = parseFloat(data.winRate.toFixed(2));
      data.avgPnL = parseFloat(data.avgPnL.toFixed(2));
    });

    res.json({
      patterns: {
        bestWinStreak,
        worstLossStreak,
        dayOfWeekPerformance,
        instrumentPerformance
      }
    });
  } catch (error) {
    console.error('Error fetching patterns data:', error);
    res.status(500).json({ 
      error: 'Failed to fetch patterns data',
      message: error.message 
    });
  }
});

// Webhooks
app.post('/api/webhooks/supabase', async (req, res) => {
  try {
    const { type, record } = req.body;
    
    if (type === 'INSERT' && record.email) {
      try {
        await pool.query(
          'INSERT INTO user_profiles (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING',
          [record.id]
        );
        console.log(`✅ Created profile for user: ${record.email}`);
      } catch (pgError) {
        console.error('Webhook profile creation failed:', pgError);
      }
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Webhook error:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server Error:', err.stack);
  res.status(500).json({
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong!'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: 'The requested resource was not found',
    path: req.path
  });
});

// Start server
const startServer = async () => {
  try {
    console.log('🚀 Starting TradingJournal Pro API...');
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    
    // Test Supabase connection
    const { data, error } = await supabaseAdmin.auth.admin.listUsers({ page: 1, perPage: 1 });
    if (error) {
      throw new Error(`Supabase connection failed: ${error.message}`);
    }
    console.log('✅ Supabase connection successful');
    
    // Initialize database
    await initializeDatabase();
    
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port: ${PORT}`);
      console.log(`🩺 Health check: http://localhost:${PORT}/api/health`);
      console.log(`💾 DB status: http://localhost:${PORT}/api/db-status`);
      console.log('✅ TradingJournal Pro API ready!');
    });
    
  } catch (error) {
    console.error('❌ Failed to start server:', error.message);
    process.exit(1);
  }
};

// Graceful shutdown
const gracefulShutdown = async (signal) => {
  console.log(`\n🛑 Received ${signal}, shutting down gracefully...`);
  
  try {
    await pool.end();
    console.log('✅ Database connections closed');
    process.exit(0);
  } catch (error) {
    console.error('❌ Error during shutdown:', error);
    process.exit(1);
  }
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Start the server
startServer();

module.exports = app;