const express = require('express');
const cors = require('cors');
const Joi = require('joi');
const math = require('mathjs');
const ss = require('simple-statistics');
const validator = require('validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Supabase configuration
const supabaseUrl = process.env.SUPABASE_URL || 'https://fsicauceosmdrhxmvreu.supabase.co';
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZzaWNhdWNlb3NtZHJoeG12cmV1Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1ODEwMjk5OSwiZXhwIjoyMDczNjc4OTk5fQ.bqzxqGvx_l8-PQ4Ms5fgorweqQCn8fWaBF1O8fs8lX0';
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZzaWNhdWNlb3NtZHJoeG12cmV1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTgxMDI5OTksImV4cCI6MjA3MzY3ODk5OX0.J_Dx9SLkzffTFcDhxMix56cmtpM4710nqafnyP5BLhk';

// Initialize Supabase clients
let supabaseAdmin = null;
let supabase = null;
let createClient = null;

try {
  const supabaseJs = require('@supabase/supabase-js');
  createClient = supabaseJs.createClient;
  
  // Admin client
  supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    }
  });
  
  // Regular client
  supabase = createClient(supabaseUrl, supabaseAnonKey);
  
  console.log('✅ Supabase clients initialized successfully');
} catch (error) {
  console.error('❌ FATAL ERROR: Failed to initialize Supabase:', error.message);
  process.exit(1);
}

// Middleware
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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
    p_and_l: safeParseFloat(trade.p_and_l)
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

    if (error || !user) {
      return res.status(403).json({ 
        error: 'Authentication failed',
        message: 'Invalid or expired token' 
      });
    }

    const userSupabase = createClient(supabaseUrl, supabaseAnonKey, {
      global: {
        headers: {
          Authorization: `Bearer ${token}`
        }
      }
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

// Simple database initialization
const initializeDatabase = async () => {
  try {
    console.log('🔧 Initializing database connection...');
    
    // Simple connection test
    const { data, error } = await supabaseAdmin.auth.admin.listUsers({ page: 1, perPage: 1 });
    if (error) {
      throw new Error(`Connection test failed: ${error.message}`);
    }
    
    console.log('✅ Database connection verified');
    console.log('ℹ️ Schema should be set up through Supabase dashboard');
    
  } catch (error) {
    console.error('⚠️ Database initialization warning:', error.message);
    console.log('ℹ️ Application will continue with limited functionality');
    // Don't exit - continue running
  }
};

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Trading Journal API is running!',
    timestamp: new Date().toISOString()
  });
});

// Database status check
app.get('/api/db-status', async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin.auth.admin.listUsers({ page: 1, perPage: 1 });
    
    res.json({ 
      connected: !error, 
      message: error ? 'Connection failed' : 'Database connected',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ 
      connected: false, 
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Get/Create user profile
app.get('/api/auth/profile', authenticateSupabaseUser, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const { data: profile, error: selectError } = await req.supabase
      .from('user_profiles')
      .select('*')
      .eq('user_id', userId)
      .single();
    
    let userProfile = profile;
    
    if (selectError && selectError.code === 'PGRST116') {
      const { data: newProfile, error: insertError } = await req.supabase
        .from('user_profiles')
        .insert([{ user_id: userId }])
        .select()
        .single();
        
      if (insertError) {
        throw insertError;
      }
      userProfile = newProfile;
    } else if (selectError) {
      throw selectError;
    }

    res.json({
      user: {
        id: req.user.id,
        email: req.user.email,
        firstName: req.user.first_name,
        lastName: req.user.last_name,
        phone: userProfile?.phone,
        tradingExperience: userProfile?.trading_experience,
        preferredMarket: userProfile?.preferred_market,
        riskTolerance: userProfile?.risk_tolerance,
        createdAt: userProfile?.created_at,
        updatedAt: userProfile?.updated_at
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

// Update user profile
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
    
    const { data: profile, error } = await req.supabase
      .from('user_profiles')
      .update(updateData)
      .eq('user_id', userId)
      .select()
      .single();
    
    if (error) {
      throw error;
    }

    res.json({
      message: 'Profile updated successfully',
      user: {
        id: req.user.id,
        email: req.user.email,
        phone: profile?.phone,
        tradingExperience: profile?.trading_experience,
        preferredMarket: profile?.preferred_market,
        riskTolerance: profile?.risk_tolerance,
        updatedAt: profile?.updated_at
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

// Get trades
app.get('/api/trades', authenticateSupabaseUser, async (req, res) => {
  try {
    const { status, strategy, limit = 1000 } = req.query;
    
    let query = req.supabase
      .from('trading_journal')
      .select('*')
      .order('s_no', { ascending: false })
      .limit(parseInt(limit));

    if (status) query = query.eq('status', status);
    if (strategy) query = query.eq('strategy', strategy);

    const { data: trades, error } = await query;
    
    if (error) throw error;

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

// Add new trade
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
      ...value,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    const { data: trade, error } = await req.supabase
      .from('trading_journal')
      .insert([tradeData])
      .select()
      .single();
    
    if (error) throw error;

    res.status(201).json({
      message: 'Trade created successfully',
      trade: formatTradeData(trade)
    });
  } catch (error) {
    console.error('Error creating trade:', error);
    res.status(500).json({ 
      error: 'Failed to create trade',
      message: error.message 
    });
  }
});

// Update trade
app.put('/api/trades/:id', authenticateSupabaseUser, async (req, res) => {
  try {
    const tradeId = req.params.id;
    
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
    
    const { data: trade, error } = await req.supabase
      .from('trading_journal')
      .update(updateData)
      .eq('s_no', tradeId)
      .select()
      .single();
    
    if (error) throw error;
    if (!trade) {
      return res.status(404).json({ error: 'Trade not found or unauthorized' });
    }

    res.json({
      message: 'Trade updated successfully',
      trade: formatTradeData(trade)
    });
  } catch (error) {
    console.error('Error updating trade:', error);
    res.status(500).json({ 
      error: 'Failed to update trade',
      message: error.message 
    });
  }
});

// Delete trade
app.delete('/api/trades/:id', authenticateSupabaseUser, async (req, res) => {
  try {
    const tradeId = req.params.id;
    
    const { data: trade, error } = await req.supabase
      .from('trading_journal')
      .delete()
      .eq('s_no', tradeId)
      .select('s_no')
      .single();
    
    if (error) throw error;
    if (!trade) {
      return res.status(404).json({ error: 'Trade not found or unauthorized' });
    }

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

// Get trading statistics
app.get('/api/analytics/stats', authenticateSupabaseUser, async (req, res) => {
  try {
    const { data: trades, error } = await req.supabase
      .from('trading_journal')
      .select('status, p_and_l');
    
    if (error) throw error;

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

// Advanced analytics endpoints (simplified)
app.get('/api/analytics/advanced-stats', authenticateSupabaseUser, async (req, res) => {
  try {
    const { data: trades, error } = await req.supabase
      .from('trading_journal')
      .select('*')
      .order('entry_dt');
    
    if (error) throw error;

    // Return basic structure for now
    res.json({
      stats: {
        basic: {
          totalTrades: trades?.length || 0,
          closedTrades: trades?.filter(t => t.status === 'closed').length || 0,
          openTrades: trades?.filter(t => t.status === 'open').length || 0,
          totalPnL: 0,
          avgPnL: 0,
          winRate: 0,
          profitFactor: 0,
          expectancy: 0
        },
        risk: {
          sharpeRatio: 0,
          maxDrawdown: 0,
          calmarRatio: 0,
          var95: 0,
          var99: 0,
          volatility: 0
        },
        performance: {
          avgWin: 0,
          avgLoss: 0,
          largestWin: 0,
          largestLoss: 0,
          riskRewardRatio: 0,
          kellyPercentage: 0,
          annualReturn: 0
        },
        time: {
          firstTradeDate: null,
          lastTradeDate: null,
          tradingDays: 0,
          avgTradesPerMonth: 0
        }
      }
    });
  } catch (error) {
    console.error('Error fetching advanced stats:', error);
    res.status(500).json({ 
      error: 'Failed to fetch advanced statistics',
      message: error.message 
    });
  }
});

// Time series endpoint (simplified)
app.get('/api/analytics/time-series', authenticateSupabaseUser, async (req, res) => {
  try {
    res.json({ data: [] });
  } catch (error) {
    console.error('Error fetching time series:', error);
    res.status(500).json({ 
      error: 'Failed to fetch time series data',
      message: error.message 
    });
  }
});

// Patterns endpoint (simplified)
app.get('/api/analytics/patterns', authenticateSupabaseUser, async (req, res) => {
  try {
    res.json({
      patterns: {
        bestWinStreak: 0,
        worstLossStreak: 0,
        dayOfWeekPerformance: {},
        instrumentPerformance: {}
      }
    });
  } catch (error) {
    console.error('Error fetching patterns:', error);
    res.status(500).json({ 
      error: 'Failed to fetch patterns data',
      message: error.message 
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server Error:', err.stack);
  res.status(500).json({
    error: 'Internal Server Error',
    message: 'Something went wrong!'
  });
});

// Start server
const startServer = async () => {
  try {
    console.log('🚀 Starting Trading Journal API...');
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    
    await initializeDatabase();
    
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port: ${PORT}`);
      console.log(`🩺 Health check: http://localhost:${PORT}/api/health`);
      console.log('✅ Server ready!');
    });
    
  } catch (error) {
    console.error('❌ Failed to start server:', error.message);
    process.exit(1);
  }
};

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('Shutting down gracefully...');
  process.exit(0);
});

startServer();