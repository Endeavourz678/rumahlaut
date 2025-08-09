// server.js - ENHANCED Fish Distribution POS System with Full CRUD
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const compression = require('compression');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(compression());
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5500', 'http://127.0.0.1:5500'],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static('public'));

// Database Connection Pool
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'fish_distribution',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true
};

let pool;
const JWT_SECRET = process.env.JWT_SECRET || 'default-secret-change-this';

// Helper function to generate batch code
function generateBatchCode(description) {
  const hash = crypto.createHash('md5').update(description.toLowerCase()).digest('hex').substring(0, 6);
  const date = new Date().toISOString().split('T')[0].replace(/-/g, '');
  return `BATCH-${date}-${hash.toUpperCase()}`;
}

// CARI fungsi initializeDatabase() di server.js
// REPLACE SELURUH fungsi dengan kode ini:

async function initializeDatabase() {
  try {
    console.log('🔄 Initializing database connection...');
    
    pool = mysql.createPool(dbConfig);
    const connection = await pool.getConnection();
    console.log('✅ Database connected successfully');
    
    // Create Users table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role ENUM('admin', 'cashier', 'manager') DEFAULT 'cashier',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    // Create Products table - Enhanced for POS
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS products (
        id INT AUTO_INCREMENT PRIMARY KEY,
        code VARCHAR(50) UNIQUE NOT NULL,
        name VARCHAR(100) NOT NULL,
        description TEXT NOT NULL,
        production_date DATE NOT NULL,
        batch_code VARCHAR(50) NOT NULL,
        price_per_kg_buy DECIMAL(10,2) NOT NULL COMMENT 'Harga beli per kg',
        price_per_kg_sell DECIMAL(10,2) NOT NULL COMMENT 'Harga jual per kg',
        stock_kg DECIMAL(10,2) NOT NULL DEFAULT 0 COMMENT 'Stok dalam kg',
        min_stock_kg DECIMAL(10,2) DEFAULT 5 COMMENT 'Minimum stok dalam kg',
        category VARCHAR(50) DEFAULT 'Ikan Segar',
        supplier VARCHAR(100),
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_batch (batch_code),
        INDEX idx_active (is_active),
        INDEX idx_category (category)
      )
    `);

    // Create Customers table - Enhanced
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS customers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        phone VARCHAR(20) NOT NULL,
        email VARCHAR(100),
        address TEXT NOT NULL,
        shipping_cost DECIMAL(10,2) NOT NULL DEFAULT 0,
        customer_type ENUM('retail', 'wholesale', 'restaurant') DEFAULT 'retail',
        credit_limit DECIMAL(12,2) DEFAULT 0,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_active (is_active),
        INDEX idx_type (customer_type)
      )
    `);

    // Create Transactions table - Enhanced with more details
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS transactions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        transaction_no VARCHAR(50) UNIQUE NOT NULL,
        customer_id INT NOT NULL,
        product_id INT NOT NULL,
        actual_weight_kg DECIMAL(10,2) NOT NULL COMMENT 'Berat aktual saat timbang',
        price_per_kg DECIMAL(10,2) NOT NULL COMMENT 'Harga per kg saat transaksi',
        original_price_per_kg DECIMAL(10,2) NOT NULL COMMENT 'Harga asli produk',
        price_adjusted BOOLEAN DEFAULT FALSE COMMENT 'Apakah harga disesuaikan manual',
        subtotal DECIMAL(10,2) NOT NULL COMMENT 'actual_weight_kg * price_per_kg',
        shipping_cost DECIMAL(10,2) NOT NULL,
        total DECIMAL(10,2) NOT NULL COMMENT 'subtotal + shipping_cost',
        payment_method ENUM('cash', 'transfer', 'credit', 'debit') NOT NULL,
        status ENUM('completed', 'pending', 'cancelled', 'refunded') DEFAULT 'pending',
        transaction_date DATE NOT NULL,
        transaction_time TIME NOT NULL,
        notes TEXT,
        weighed_by VARCHAR(100) COMMENT 'Nama penimbang',
        cashier_id INT,
        discount_percent DECIMAL(5,2) DEFAULT 0,
        discount_amount DECIMAL(10,2) DEFAULT 0,
        tax_percent DECIMAL(5,2) DEFAULT 0,
        tax_amount DECIMAL(10,2) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE RESTRICT,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE RESTRICT,
        FOREIGN KEY (cashier_id) REFERENCES users(id) ON DELETE SET NULL,
        INDEX idx_transaction_no (transaction_no),
        INDEX idx_status (status),
        INDEX idx_date (transaction_date)
      )
    `);

    // Create Transaction Items table for multi-item transactions
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS transaction_items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        transaction_id INT NOT NULL,
        product_id INT NOT NULL,
        weight_kg DECIMAL(10,2) NOT NULL,
        price_per_kg DECIMAL(10,2) NOT NULL,
        subtotal DECIMAL(10,2) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (transaction_id) REFERENCES transactions(id) ON DELETE CASCADE,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE RESTRICT
      )
    `);

    // Create Stock Movements table for inventory tracking
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS stock_movements (
        id INT AUTO_INCREMENT PRIMARY KEY,
        product_id INT NOT NULL,
        movement_type ENUM('in', 'out', 'adjustment') NOT NULL,
        quantity_kg DECIMAL(10,2) NOT NULL,
        reference_type ENUM('purchase', 'sale', 'adjustment', 'return') NOT NULL,
        reference_id INT,
        notes TEXT,
        created_by INT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE RESTRICT,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
      )
    `);

    // Create default admin user
    const [existingAdmin] = await connection.execute(
      'SELECT id FROM users WHERE username = ?', ['admin']
    );

    if (existingAdmin.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await connection.execute(
        'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
        ['admin', 'admin@fishco.com', hashedPassword, 'admin']
      );
      console.log('✅ Default admin user created: admin/admin123');
    }

    // Insert sample data
    const [productCount] = await connection.execute('SELECT COUNT(*) as count FROM products');
    if (productCount[0].count === 0) {
      const sampleProducts = [
        {
          code: 'IKN001',
          name: 'Ikan Tuna Segar',
          description: 'Ikan tuna segar import kualitas sashimi grade A',
          production_date: '2024-01-15',
          price_per_kg_buy: 85000,
          price_per_kg_sell: 120000,
          stock_kg: 25.5,
          category: 'Ikan Premium',
          supplier: 'PT Seafood Import'
        },
        {
          code: 'IKN002', 
          name: 'Ikan Salmon Premium',
          description: 'Ikan salmon premium Norway fresh import',
          production_date: '2024-01-16',
          price_per_kg_buy: 150000,
          price_per_kg_sell: 200000,
          stock_kg: 18.8,
          category: 'Ikan Premium',
          supplier: 'Norway Fish Co'
        },
        {
          code: 'IKN003',
          name: 'Ikan Kakap Putih',
          description: 'Ikan kakap putih lokal segar tangkapan hari ini',
          production_date: '2024-01-17',
          price_per_kg_buy: 65000,
          price_per_kg_sell: 90000,
          stock_kg: 30.2,
          category: 'Ikan Lokal',
          supplier: 'Nelayan Lokal'
        }
      ];

      for (const product of sampleProducts) {
        const batchCode = generateBatchCode(product.description);
        await connection.execute(`
          INSERT INTO products (code, name, description, production_date, batch_code, 
          price_per_kg_buy, price_per_kg_sell, stock_kg, category, supplier) 
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [product.code, product.name, product.description, product.production_date, 
           batchCode, product.price_per_kg_buy, product.price_per_kg_sell, product.stock_kg,
           product.category, product.supplier]
        );
      }
      console.log('✅ Sample products created');
    }

    const [customerCount] = await connection.execute('SELECT COUNT(*) as count FROM customers');
    if (customerCount[0].count === 0) {
      await connection.execute(`
        INSERT INTO customers (name, phone, address, shipping_cost, customer_type, credit_limit) VALUES
        ('Restoran Seafood Bahari', '081234567890', 'Jl. Pantai Indah No. 15, Jakarta', 15000, 'restaurant', 5000000),
        ('Hotel Grand Ocean', '081234567891', 'Jl. Sudirman No. 100, Jakarta', 20000, 'wholesale', 10000000),
        ('Pasar Ikan Modern', '081234567892', 'Jl. Pasar Ikan No. 25, Jakarta', 10000, 'wholesale', 3000000),
        ('Customer Retail', '081234567893', 'Jl. Permata No. 50, Jakarta', 5000, 'retail', 0)
      `);
      console.log('✅ Sample customers created');
    }

    // Auto-fix transaction data - PASTIKAN connection masih dalam scope
    try {
      console.log('🔧 Auto-fixing transaction data...');
      
      // Fix NULL transaction_no
      await connection.execute(`
        UPDATE transactions 
        SET transaction_no = CONCAT('TRX', id)
        WHERE transaction_no IS NULL OR transaction_no = ''
      `);
      
      // Fix NULL dates
      await connection.execute(`
        UPDATE transactions 
        SET transaction_date = DATE(created_at),
            transaction_time = TIME(created_at)
        WHERE transaction_date IS NULL OR transaction_time IS NULL
      `);
      
      // Fix NULL prices
      await connection.execute(`
        UPDATE transactions t
        LEFT JOIN products p ON t.product_id = p.id
        SET t.original_price_per_kg = COALESCE(t.price_per_kg, p.price_per_kg_sell)
        WHERE t.original_price_per_kg IS NULL OR t.original_price_per_kg = 0
      `);
      
      console.log('✅ Transaction data fixed');
    } catch (fixError) {
      console.error('⚠️  Warning: Could not fix transaction data:', fixError.message);
      // Don't fail initialization if fix fails
    }

    connection.release();
    console.log('✅ Database initialization completed');
    
  } catch (error) {
    console.error('❌ Database initialization failed:', error.message);
    process.exit(1);
  }
}

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Routes
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

// Health Check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    message: '🐟 Enhanced Fish Distribution POS API',
    timestamp: new Date().toISOString(),
    version: '3.0.0 - Full POS System'
  });
});

app.get('/api/test/db', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [result] = await connection.execute('SELECT 1 as test');
    connection.release();
    res.json({ 
      status: 'Database connected',
      result: result[0] 
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'Database error',
      error: error.message 
    });
  }
});

app.get('/api/test/transactions', async (req, res) => {
  try {
    const [transactions] = await pool.execute(`
      SELECT 
        t.id,
        COALESCE(t.transaction_no, CONCAT('TRX', t.id)) as transaction_no,
        COALESCE(t.transaction_date, DATE(t.created_at)) as transaction_date,
        t.actual_weight_kg,
        t.total,
        t.status,
        COALESCE(c.name, 'Unknown Customer') as customer_name,
        COALESCE(p.name, 'Unknown Product') as product_name
      FROM transactions t
      LEFT JOIN customers c ON t.customer_id = c.id
      LEFT JOIN products p ON t.product_id = p.id
      ORDER BY t.created_at DESC
      LIMIT 10
    `);
    
    res.json({
      message: 'Test endpoint working',
      count: transactions.length,
      data: transactions
    });
  } catch (error) {
    res.status(500).json({ 
      error: error.message,
      sqlMessage: error.sqlMessage,
      code: error.code,
      errno: error.errno
    });
  }
});

app.get('/api/test/structure', async (req, res) => {
  try {
    const [columns] = await pool.execute('SHOW COLUMNS FROM transactions');
    res.json({
      message: 'Transaction table structure',
      columns: columns.map(col => ({
        field: col.Field,
        type: col.Type,
        null: col.Null,
        key: col.Key,
        default: col.Default
      }))
    });
  } catch (error) {
    res.status(500).json({ 
      error: error.message 
    });
  }
});

// Authentication Routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    const [users] = await pool.execute(
      'SELECT * FROM users WHERE username = ? OR email = ?',
      [username, username]
    );

    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = users[0];
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PRODUCTS ROUTES - Enhanced with full CRUD
app.get('/api/products', authenticateToken, async (req, res) => {
  try {
    const [products] = await pool.execute(`
      SELECT id, code, name, description, production_date, batch_code,
             price_per_kg_buy, price_per_kg_sell, stock_kg, min_stock_kg,
             category, supplier, created_at, updated_at
      FROM products 
      WHERE is_active = TRUE 
      ORDER BY created_at DESC
    `);
    res.json(products);
  } catch (error) {
    console.error('Get products error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    const [products] = await pool.execute(
      'SELECT * FROM products WHERE id = ? AND is_active = TRUE',
      [req.params.id]
    );
    
    if (products.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    res.json(products[0]);
  } catch (error) {
    console.error('Get product error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/products', authenticateToken, async (req, res) => {
  try {
    const {
      code, name, description, production_date,
      price_per_kg_buy, price_per_kg_sell, stock_kg,
      category, supplier, min_stock_kg
    } = req.body;

    if (!code || !name || !description || !production_date || !price_per_kg_buy || !price_per_kg_sell || stock_kg === undefined) {
      return res.status(400).json({ error: 'All required fields must be provided' });
    }

    const batchCode = generateBatchCode(description);

    const [result] = await pool.execute(
      `INSERT INTO products (code, name, description, production_date, batch_code,
       price_per_kg_buy, price_per_kg_sell, stock_kg, category, supplier, min_stock_kg) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [code, name, description, production_date, batchCode, price_per_kg_buy, 
       price_per_kg_sell, stock_kg, category || 'Ikan Segar', supplier || '', min_stock_kg || 5]
    );

    // Record stock movement
    await pool.execute(
      `INSERT INTO stock_movements (product_id, movement_type, quantity_kg, reference_type, notes, created_by)
       VALUES (?, 'in', ?, 'purchase', 'Initial stock', ?)`,
      [result.insertId, stock_kg, req.user.id]
    );

    res.status(201).json({ 
      message: 'Product created successfully', 
      id: result.insertId,
      batch_code: batchCode
    });
  } catch (error) {
    console.error('Create product error:', error);
    if (error.code === 'ER_DUP_ENTRY') {
      res.status(400).json({ error: 'Product code already exists' });
    } else {
      res.status(500).json({ error: error.message });
    }
  }
});

app.put('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    const {
      code, name, description, production_date,
      price_per_kg_buy, price_per_kg_sell, stock_kg,
      category, supplier, min_stock_kg
    } = req.body;

    // Get current product for stock comparison
    const [currentProduct] = await pool.execute(
      'SELECT * FROM products WHERE id = ? AND is_active = TRUE', 
      [req.params.id]
    );

    if (currentProduct.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }

    const oldStock = parseFloat(currentProduct[0].stock_kg);
    const newStock = parseFloat(stock_kg);
    const stockDifference = newStock - oldStock;

    // Update product
    let batchCode = currentProduct[0].batch_code;
    if (description !== currentProduct[0].description) {
      batchCode = generateBatchCode(description);
    }

    const [result] = await pool.execute(
      `UPDATE products SET code = ?, name = ?, description = ?, production_date = ?, 
       batch_code = ?, price_per_kg_buy = ?, price_per_kg_sell = ?, stock_kg = ?,
       category = ?, supplier = ?, min_stock_kg = ?
       WHERE id = ?`,
      [code, name, description, production_date, batchCode, price_per_kg_buy, 
       price_per_kg_sell, stock_kg, category, supplier, min_stock_kg, req.params.id]
    );

    // Record stock movement if stock changed
    if (stockDifference !== 0) {
      await pool.execute(
        `INSERT INTO stock_movements (product_id, movement_type, quantity_kg, reference_type, notes, created_by)
         VALUES (?, ?, ?, 'adjustment', 'Stock updated via edit', ?)`,
        [req.params.id, stockDifference > 0 ? 'in' : 'out', Math.abs(stockDifference), req.user.id]
      );
    }

    res.json({ 
      message: 'Product updated successfully',
      batch_code: batchCode
    });
  } catch (error) {
    console.error('Update product error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    // Check if product has transactions
    const [transactions] = await pool.execute(
      'SELECT COUNT(*) as count FROM transactions WHERE product_id = ?',
      [req.params.id]
    );

    if (transactions[0].count > 0) {
      return res.status(400).json({ 
        error: 'Cannot delete product with existing transactions. Product will be deactivated instead.' 
      });
    }

    // Soft delete
    const [result] = await pool.execute(
      'UPDATE products SET is_active = FALSE WHERE id = ?', 
      [req.params.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }

    res.json({ message: 'Product deleted successfully' });
  } catch (error) {
    console.error('Delete product error:', error);
    res.status(500).json({ error: error.message });
  }
});

// CUSTOMERS ROUTES - Enhanced with full CRUD
app.get('/api/customers', authenticateToken, async (req, res) => {
  try {
    const [customers] = await pool.execute(`
      SELECT c.*, COUNT(t.id) as total_transactions,
             COALESCE(SUM(t.total), 0) as total_spent
      FROM customers c 
      LEFT JOIN transactions t ON c.id = t.customer_id AND t.status = 'completed'
      WHERE c.is_active = TRUE
      GROUP BY c.id 
      ORDER BY c.created_at DESC
    `);
    res.json(customers);
  } catch (error) {
    console.error('Get customers error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/customers/:id', authenticateToken, async (req, res) => {
  try {
    const [customers] = await pool.execute(
      'SELECT * FROM customers WHERE id = ? AND is_active = TRUE',
      [req.params.id]
    );
    
    if (customers.length === 0) {
      return res.status(404).json({ error: 'Customer not found' });
    }
    
    res.json(customers[0]);
  } catch (error) {
    console.error('Get customer error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/customers', authenticateToken, async (req, res) => {
  try {
    const { 
      name, phone, address, shipping_cost, email, 
      customer_type, credit_limit 
    } = req.body;

    if (!name || !phone || !address || shipping_cost === undefined) {
      return res.status(400).json({ error: 'Name, phone, address, and shipping cost are required' });
    }

    const [result] = await pool.execute(
      `INSERT INTO customers (name, phone, email, address, shipping_cost, customer_type, credit_limit) 
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [name, phone, email || null, address, shipping_cost, customer_type || 'retail', credit_limit || 0]
    );

    res.status(201).json({ 
      message: 'Customer created successfully', 
      id: result.insertId 
    });
  } catch (error) {
    console.error('Create customer error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/customers/:id', authenticateToken, async (req, res) => {
  try {
    const { 
      name, phone, email, address, shipping_cost, 
      customer_type, credit_limit 
    } = req.body;

    const [result] = await pool.execute(
      `UPDATE customers SET name = ?, phone = ?, email = ?, address = ?, 
       shipping_cost = ?, customer_type = ?, credit_limit = ? 
       WHERE id = ?`,
      [name, phone, email || null, address, shipping_cost, customer_type, credit_limit, req.params.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Customer not found' });
    }

    res.json({ message: 'Customer updated successfully' });
  } catch (error) {
    console.error('Update customer error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/customers/:id', authenticateToken, async (req, res) => {
  try {
    // Check if customer has transactions
    const [transactions] = await pool.execute(
      'SELECT COUNT(*) as count FROM transactions WHERE customer_id = ?',
      [req.params.id]
    );

    if (transactions[0].count > 0) {
      return res.status(400).json({ 
        error: 'Cannot delete customer with existing transactions. Customer will be deactivated instead.' 
      });
    }

    // Soft delete
    const [result] = await pool.execute(
      'UPDATE customers SET is_active = FALSE WHERE id = ?', 
      [req.params.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Customer not found' });
    }

    res.json({ message: 'Customer deleted successfully' });
  } catch (error) {
    console.error('Delete customer error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/transactions/grouped', authenticateToken, async (req, res) => {
  try {
    console.log('GET /api/transactions/grouped - Loading grouped transactions...');
    
    const { date, status, customer_id, limit = 100 } = req.query;
    
    // Query yang menggabungkan items per transaksi
    let query = `
      SELECT 
      MIN(t.id) as id,
      COALESCE(t.transaction_no, CONCAT('TRX', MIN(t.id))) as transaction_no,
        DATE(COALESCE(t.transaction_date, t.created_at)) as transaction_date,
        TIME(COALESCE(t.transaction_time, t.created_at)) as transaction_time,
        t.customer_id,
        c.name as customer_name,
        c.phone as customer_phone,
        c.customer_type,
        
        -- Gabungkan informasi produk jika ada multiple items
        GROUP_CONCAT(DISTINCT p.name ORDER BY p.name SEPARATOR ', ') as product_names,
        GROUP_CONCAT(DISTINCT p.code ORDER BY p.code SEPARATOR ', ') as product_codes,
        COUNT(DISTINCT t.product_id) as item_count,
        
        -- Total quantities dan amounts
        SUM(t.actual_weight_kg) as total_weight_kg,
        SUM(t.subtotal) as total_subtotal,
        MAX(t.shipping_cost) as shipping_cost,
        SUM(t.discount_amount) as total_discount,
        SUM(t.tax_amount) as total_tax,
        SUM(t.total) as grand_total,
        
        -- Payment and status (should be same for all items in a transaction)
        MAX(t.payment_method) as payment_method,
        MAX(t.status) as status,
        MAX(t.notes) as notes,
        MAX(t.weighed_by) as weighed_by,
        MAX(u.username) as cashier_name,
        
        -- Timestamps
        MAX(t.created_at) as created_at,
        MAX(t.updated_at) as updated_at
        
      FROM transactions t
      LEFT JOIN customers c ON t.customer_id = c.id
      LEFT JOIN products p ON t.product_id = p.id
      LEFT JOIN users u ON t.cashier_id = u.id
      WHERE 1=1
    `;
    
    const params = [];
    const groupBy = ' GROUP BY t.transaction_no, t.customer_id, t.transaction_date';

    if (date) {
      query += ' AND DATE(t.transaction_date) = ?';
      params.push(date);
    }
    if (status) {
      query += ' AND t.status = ?';
      params.push(status);
    }
    if (customer_id) {
      query += ' AND t.customer_id = ?';
      params.push(customer_id);
    }

    // Add GROUP BY before ORDER BY
    query += groupBy;
    query += ' ORDER BY MAX(t.created_at) DESC LIMIT ?';
    params.push(parseInt(limit));

    const [transactions] = await pool.execute(query, params);
    console.log(`Found ${transactions.length} grouped transactions`);
    
    res.json(transactions);
  } catch (error) {
    console.error('GET /api/transactions/grouped error:', error);
    res.status(500).json({ 
      error: 'Failed to load grouped transactions: ' + error.message,
      sqlError: error.sqlMessage || null
    });
  }
});

// TRANSACTIONS ROUTES - Enhanced with full CRUD
app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    console.log('📋 Loading transactions...');
    
    const { date, status, customer_id, limit = 100 } = req.query;
    let query = `
      SELECT 
        t.id,
        IFNULL(t.transaction_no, CONCAT('TRX', t.id)) as transaction_no,
        t.customer_id,
        t.product_id,
        DATE(IFNULL(t.transaction_date, t.created_at)) as transaction_date,
        TIME(IFNULL(t.transaction_time, t.created_at)) as transaction_time,
        t.actual_weight_kg,
        t.price_per_kg,
        t.subtotal,
        t.shipping_cost,
        t.total,
        t.payment_method,
        t.status,
        t.notes,
        t.weighed_by,
        c.name as customer_name,
        c.phone as customer_phone,
        p.name as product_name,
        p.code as product_code,
        u.username as cashier_name
      FROM transactions t 
      LEFT JOIN customers c ON t.customer_id = c.id 
      LEFT JOIN products p ON t.product_id = p.id 
      LEFT JOIN users u ON t.cashier_id = u.id
      WHERE 1=1
    `;
    const params = [];

    if (date) {
      query += ' AND DATE(t.transaction_date) = ?';
      params.push(date);
    }
    if (status) {
      query += ' AND t.status = ?';
      params.push(status);
    }
    if (customer_id) {
      query += ' AND t.customer_id = ?';
      params.push(customer_id);
    }

    query += ' ORDER BY t.created_at DESC LIMIT ?';
    params.push(parseInt(limit));

    console.log('Executing query with params:', params);
    const [transactions] = await pool.execute(query, params);
    console.log(`Found ${transactions.length} transactions`);
    
    res.json(transactions);
  } catch (error) {
    console.error('❌ Get transactions error:', error);
    res.status(500).json({ 
      error: 'Database error: ' + error.message,
      code: error.code 
    });
  }
});

app.get('/api/transactions/simple', authenticateToken, async (req, res) => {
  try {
    console.log('📋 Loading simple transactions...');
    
    const [transactions] = await pool.execute(`
      SELECT 
        t.id,
        IFNULL(t.transaction_no, CONCAT('TRX', t.id)) as transaction_no,
        DATE(IFNULL(t.transaction_date, t.created_at)) as transaction_date,
        TIME(IFNULL(t.transaction_time, t.created_at)) as transaction_time,
        t.actual_weight_kg,
        t.price_per_kg,
        t.total,
        t.payment_method,
        t.status,
        t.notes,
        t.weighed_by,
        c.name as customer_name,
        c.phone as customer_phone,
        p.name as product_name,
        p.code as product_code
      FROM transactions t
      LEFT JOIN customers c ON t.customer_id = c.id
      LEFT JOIN products p ON t.product_id = p.id
      ORDER BY t.created_at DESC
      LIMIT 100
    `);
    
    console.log(`Simple endpoint: Found ${transactions.length} transactions`);
    
    res.json({
      success: true,
      count: transactions.length,
      data: transactions
    });
  } catch (error) {
    console.error('❌ Simple transactions error:', error);
    res.status(500).json({ 
      success: false,
      error: error.message,
      data: [] 
    });
  }
});

// Get single transaction
app.get('/api/transactions/:id', authenticateToken, async (req, res) => {
  try {
    const [transactions] = await pool.execute(`
      SELECT 
        t.*,
        COALESCE(t.transaction_no, CONCAT('TRX', t.id)) as transaction_no,
        c.name as customer_name, 
        c.phone as customer_phone, 
        c.address as customer_address,
        p.name as product_name, 
        p.code as product_code, 
        p.description as product_description,
        u.username as cashier_name
      FROM transactions t
      LEFT JOIN customers c ON t.customer_id = c.id
      LEFT JOIN products p ON t.product_id = p.id
      LEFT JOIN users u ON t.cashier_id = u.id
      WHERE t.id = ?
    `, [req.params.id]);
    
    if (transactions.length === 0) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    
    res.json(transactions[0]);
  } catch (error) {
    console.error('Get transaction details error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/transactions', authenticateToken, async (req, res) => {
  const connection = await pool.getConnection();
  
  try {
    await connection.beginTransaction();
    
    const {
      customer_id, product_id, actual_weight_kg, custom_price_per_kg,
      payment_method, status, notes, weighed_by, discount_percent,
      tax_percent
    } = req.body;

    // Generate transaction number
    const now = new Date();
    const transactionNo = 'TRX' + now.getFullYear() + 
      String(now.getMonth()+1).padStart(2,'0') + 
      String(now.getDate()).padStart(2,'0') + 
      String(now.getHours()).padStart(2,'0') + 
      String(now.getMinutes()).padStart(2,'0') + 
      String(now.getSeconds()).padStart(2,'0');

    // Validation
    if (!customer_id || !product_id || !actual_weight_kg || !payment_method) {
      return res.status(400).json({ 
        error: 'Customer, product, actual weight, and payment method are required' 
      });
    }

    const parsedWeight = parseFloat(actual_weight_kg);
    if (isNaN(parsedWeight) || parsedWeight <= 0) {
      return res.status(400).json({ error: 'Actual weight must be a valid number greater than 0' });
    }

    // Get customer and product data with error handling
    const [customers] = await connection.execute(
      'SELECT * FROM customers WHERE id = ?', 
      [customer_id]
    );
    const [products] = await connection.execute(
      'SELECT * FROM products WHERE id = ?', 
      [product_id]
    );

    if (customers.length === 0) {
      return res.status(400).json({ error: 'Customer not found' });
    }
    if (products.length === 0) {
      return res.status(400).json({ error: 'Product not found' });
    }

    const customer = customers[0];
    const product = products[0];

    // Check stock availability
    if (parseFloat(product.stock_kg) < parsedWeight) {
      return res.status(400).json({ 
        error: `Insufficient stock. Available: ${product.stock_kg} kg, Requested: ${parsedWeight} kg` 
      });
    }

    // Calculate prices
    const originalPrice = parseFloat(product.price_per_kg_sell);
    const pricePerKg = custom_price_per_kg && parseFloat(custom_price_per_kg) > 0 
      ? parseFloat(custom_price_per_kg) 
      : originalPrice;
    const priceAdjusted = pricePerKg !== originalPrice;

    const weight = parseFloat(parsedWeight);
    const subtotal = Math.round(weight * pricePerKg);
    
    // Calculate discount and tax
    const discountAmount = discount_percent ? Math.round(subtotal * parseFloat(discount_percent) / 100) : 0;
    const taxableAmount = subtotal - discountAmount;
    const taxAmount = tax_percent ? Math.round(taxableAmount * parseFloat(tax_percent) / 100) : 0;
    const shippingCost = parseFloat(customer.shipping_cost) || 0;
    const total = subtotal - discountAmount + taxAmount + shippingCost;

    const currentDate = new Date();
    const transactionDate = currentDate.toISOString().split('T')[0];
    const transactionTime = currentDate.toTimeString().split(' ')[0];

    // Insert transaction
    const [result] = await connection.execute(`
      INSERT INTO transactions 
      (transaction_no, customer_id, product_id, actual_weight_kg, price_per_kg, original_price_per_kg,
       price_adjusted, subtotal, shipping_cost, total, payment_method, status, transaction_date, 
       transaction_time, notes, weighed_by, cashier_id, discount_percent, discount_amount, 
       tax_percent, tax_amount) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        transactionNo, customer_id, product_id, weight, pricePerKg, originalPrice, priceAdjusted,
        subtotal, shippingCost, total, payment_method, status || 'completed', transactionDate,
        transactionTime, notes || null, weighed_by || req.user.username, req.user.id,
        discount_percent || 0, discountAmount, tax_percent || 0, taxAmount
      ]
    );

    // Update product stock
    await connection.execute(
      'UPDATE products SET stock_kg = stock_kg - ? WHERE id = ?',
      [weight, product_id]
    );

    // Record stock movement
    await connection.execute(
      `INSERT INTO stock_movements (product_id, movement_type, quantity_kg, reference_type, reference_id, notes, created_by)
       VALUES (?, 'out', ?, 'sale', ?, ?, ?)`,
      [product_id, weight, result.insertId, `Sale - Transaction ${transactionNo}`, req.user.id]
    );

    await connection.commit();
    
    res.status(201).json({ 
      message: 'Transaction created successfully', 
      id: result.insertId,
      transaction_no: transactionNo,
      total: total
    });
    
  } catch (error) {
    await connection.rollback();
    console.error('Create transaction failed:', error);
    res.status(500).json({ error: error.message });
  } finally {
    connection.release();
  }
});

app.get('/api/transactions/:id/details', authenticateToken, async (req, res) => {
  try {
    // Get main transaction info
    const [mainInfo] = await pool.execute(`
      SELECT 
        t.transaction_no,
        t.transaction_date,
        t.transaction_time,
        c.name as customer_name,
        c.phone as customer_phone,
        c.address as customer_address,
        c.customer_type,
        t.payment_method,
        t.status,
        t.notes,
        t.weighed_by,
        u.username as cashier_name,
        MAX(t.shipping_cost) as shipping_cost,
        SUM(t.discount_amount) as total_discount,
        SUM(t.tax_amount) as total_tax,
        SUM(t.total) as grand_total
      FROM transactions t
      LEFT JOIN customers c ON t.customer_id = c.id
      LEFT JOIN users u ON t.cashier_id = u.id
      WHERE t.transaction_no = (
        SELECT transaction_no FROM transactions WHERE id = ?
      )
      GROUP BY t.transaction_no
    `, [req.params.id]);
    
    if (mainInfo.length === 0) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    
    // Get all items in this transaction
    const [items] = await pool.execute(`
      SELECT 
        t.id,
        p.code as product_code,
        p.name as product_name,
        t.actual_weight_kg,
        t.price_per_kg,
        t.original_price_per_kg,
        t.price_adjusted,
        t.subtotal
      FROM transactions t
      LEFT JOIN products p ON t.product_id = p.id
      WHERE t.transaction_no = ?
      ORDER BY t.id
    `, [mainInfo[0].transaction_no]);
    
    res.json({
      ...mainInfo[0],
      items: items
    });
  } catch (error) {
    console.error('Get transaction details error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/transactions/:id', authenticateToken, async (req, res) => {
  const connection = await pool.getConnection();
  
  try {
    await connection.beginTransaction();

    const { status, payment_method, notes } = req.body;

    // Get current transaction
    const [currentTransaction] = await connection.execute(
      'SELECT * FROM transactions WHERE id = ?',
      [req.params.id]
    );

    if (currentTransaction.length === 0) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    const transaction = currentTransaction[0];

    // Update transaction
    const [result] = await connection.execute(
      'UPDATE transactions SET status = ?, payment_method = ?, notes = ? WHERE id = ?',
      [status || transaction.status, payment_method || transaction.payment_method, 
       notes !== undefined ? notes : transaction.notes, req.params.id]
    );

    await connection.commit();

    res.json({ message: 'Transaction updated successfully' });
  } catch (error) {
    await connection.rollback();
    console.error('Update transaction error:', error);
    res.status(500).json({ error: error.message });
  } finally {
    connection.release();
  }
});

app.delete('/api/transactions/:id', authenticateToken, async (req, res) => {
  const connection = await pool.getConnection();
  
  try {
    await connection.beginTransaction();

    // Get transaction details
    const [transactions] = await connection.execute(
      'SELECT * FROM transactions WHERE id = ?',
      [req.params.id]
    );

    if (transactions.length === 0) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    const transaction = transactions[0];

    // Restore stock if transaction was completed
    if (transaction.status === 'completed') {
      await connection.execute(
        'UPDATE products SET stock_kg = stock_kg + ? WHERE id = ?',
        [transaction.actual_weight_kg, transaction.product_id]
      );

      // Record stock movement
      await connection.execute(
        `INSERT INTO stock_movements (product_id, movement_type, quantity_kg, reference_type, reference_id, notes, created_by)
         VALUES (?, 'in', ?, 'return', ?, ?, ?)`,
        [transaction.product_id, transaction.actual_weight_kg, transaction.id, 
         `Return - Deleted Transaction ${transaction.transaction_no}`, req.user.id]
      );
    }

    // Delete transaction
    await connection.execute(
      'DELETE FROM transactions WHERE id = ?',
      [req.params.id]
    );

    await connection.commit();

    res.json({ message: 'Transaction deleted successfully and stock restored' });
  } catch (error) {
    await connection.rollback();
    console.error('Delete transaction error:', error);
    res.status(500).json({ error: error.message });
  } finally {
    connection.release();
  }
});

// TAMBAHKAN KODE INI KE SERVER.JS
// Cari bagian setelah endpoint DELETE /api/transactions/:id (sekitar baris 850-900)
// Tambahkan kode berikut:

// ============= MULAI KODE YANG DITAMBAHKAN =============

// Simple transactions endpoint untuk fallback
app.get('/api/transactions/simple', authenticateToken, async (req, res) => {
  try {
    const [transactions] = await pool.execute(`
      SELECT 
        t.id,
        t.transaction_no,
        t.transaction_date,
        t.transaction_time,
        t.actual_weight_kg,
        t.price_per_kg,
        t.total,
        t.payment_method,
        t.status,
        t.notes,
        t.weighed_by,
        c.name as customer_name,
        c.phone as customer_phone,
        p.name as product_name,
        p.code as product_code
      FROM transactions t
      JOIN customers c ON t.customer_id = c.id
      JOIN products p ON t.product_id = p.id
      ORDER BY t.created_at DESC
      LIMIT 100
    `);
    
    res.json({
      success: true,
      count: transactions.length,
      data: transactions
    });
  } catch (error) {
    console.error('Simple transactions error:', error);
    res.status(500).json({ 
      success: false,
      error: error.message,
      data: [] 
    });
  }
});

// Debug endpoint untuk check database structure
app.get('/api/debug/tables', authenticateToken, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const tables = {};
    
    // Get all tables
    const [tableList] = await pool.execute('SHOW TABLES');
    
    for (const row of tableList) {
      const tableName = Object.values(row)[0];
      
      // Get table structure
      const [columns] = await pool.execute(`DESCRIBE ${tableName}`);
      
      // Get row count
      const [count] = await pool.execute(`SELECT COUNT(*) as count FROM ${tableName}`);
      
      tables[tableName] = {
        columns: columns,
        rowCount: count[0].count
      };
    }
    
    res.json({
      database: process.env.DB_NAME || 'fish_distribution',
      tables: tables
    });
  } catch (error) {
    console.error('Debug tables error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Fix the existing dashboard endpoint - REPLACE the existing one
app.get('/api/reports/dashboard', authenticateToken, async (req, res) => {
  try {
    // Initialize response object with defaults
    const dashboardData = {
      totalProducts: 0,
      totalCustomers: 0,
      totalTransactions: 0,
      totalRevenue: 0,
      totalStockKg: 0,
      lowStock: [],
      recentTransactions: [],
      fallback: false
    };

    try {
      // Get product count
      const [productCount] = await pool.execute(
        'SELECT COUNT(*) as count FROM products WHERE is_active = TRUE'
      );
      dashboardData.totalProducts = productCount[0].count;
    } catch (err) {
      console.error('Error getting product count:', err);
    }

    try {
      // Get customer count
      const [customerCount] = await pool.execute(
        'SELECT COUNT(*) as count FROM customers WHERE is_active = TRUE'
      );
      dashboardData.totalCustomers = customerCount[0].count;
    } catch (err) {
      console.error('Error getting customer count:', err);
    }

    try {
      // Get today's transaction count
      const [transactionCount] = await pool.execute(
        'SELECT COUNT(*) as count FROM transactions WHERE DATE(transaction_date) = CURDATE()'
      );
      dashboardData.totalTransactions = transactionCount[0].count;
    } catch (err) {
      console.error('Error getting transaction count:', err);
    }
    
    try {
      // Get today's revenue
      const [totalRevenue] = await pool.execute(
        'SELECT COALESCE(SUM(total), 0) as total FROM transactions WHERE status = "completed" AND DATE(transaction_date) = CURDATE()'
      );
      dashboardData.totalRevenue = parseFloat(totalRevenue[0].total) || 0;
    } catch (err) {
      console.error('Error getting revenue:', err);
    }
    
    try {
      // Get low stock products
      const [lowStock] = await pool.execute(
        'SELECT * FROM products WHERE stock_kg < min_stock_kg AND is_active = TRUE ORDER BY stock_kg ASC LIMIT 10'
      );
      dashboardData.lowStock = lowStock;
    } catch (err) {
      console.error('Error getting low stock:', err);
    }
    
    try {
      // Get recent transactions
      const [recentTransactions] = await pool.execute(`
        SELECT t.total, t.actual_weight_kg, c.name as customer_name, p.name as product_name, t.created_at
        FROM transactions t 
        JOIN customers c ON t.customer_id = c.id 
        JOIN products p ON t.product_id = p.id 
        ORDER BY t.created_at DESC LIMIT 5
      `);
      dashboardData.recentTransactions = recentTransactions;
    } catch (err) {
      console.error('Error getting recent transactions:', err);
    }

    try {
      // Get total stock
      const [totalStock] = await pool.execute(
        'SELECT COALESCE(SUM(stock_kg), 0) as total_kg FROM products WHERE is_active = TRUE'
      );
      dashboardData.totalStockKg = parseFloat(totalStock[0].total_kg) || 0;
    } catch (err) {
      console.error('Error getting total stock:', err);
    }

    res.json(dashboardData);
  } catch (error) {
    console.error('Dashboard error:', error);
    
    // Return minimal data instead of error
    res.json({
      totalProducts: 0,
      totalCustomers: 0,
      totalTransactions: 0,
      totalRevenue: 0,
      totalStockKg: 0,
      lowStock: [],
      recentTransactions: [],
      fallback: true,
      error: error.message
    });
  }
});

// Quick fix function to add to initializeDatabase
async function quickFixDatabase() {
  const connection = await pool.getConnection();
  try {
    console.log('🔧 Running quick database fixes...');
    
    // Fix transaction numbers
    await connection.execute(`
      UPDATE transactions 
      SET transaction_no = CONCAT('TRX', 
        YEAR(created_at), 
        LPAD(MONTH(created_at), 2, '0'),
        LPAD(DAY(created_at), 2, '0'),
        LPAD(id, 6, '0'))
      WHERE transaction_no IS NULL OR transaction_no = ''
    `);
    
    // Fix dates
    await connection.execute(`
      UPDATE transactions 
      SET transaction_date = DATE(created_at),
          transaction_time = TIME(created_at)
      WHERE transaction_date IS NULL OR transaction_time IS NULL
    `);
    
    // Fix original prices
    await connection.execute(`
      UPDATE transactions t
      JOIN products p ON t.product_id = p.id
      SET t.original_price_per_kg = t.price_per_kg
      WHERE t.original_price_per_kg IS NULL OR t.original_price_per_kg = 0
    `);
    
    console.log('✅ Database fixes completed');
  } catch (error) {
    console.error('Quick fix error:', error);
  } finally {
    connection.release();
  }
}

// ============= AKHIR KODE YANG DITAMBAHKAN =============

// JUGA, update fungsi startServer() untuk memanggil quickFixDatabase:
// Cari fungsi startServer() dan ubah menjadi:

async function startServer() {
  try {
    await initializeDatabase();
    await quickFixDatabase(); // TAMBAHKAN INI
    
    app.listen(PORT, () => {
      console.log('\n🐟 ================================');
      console.log('🚀 Enhanced Fish Distribution POS Started!');
      console.log(`📡 Server: http://localhost:${PORT}`);
      console.log(`🔑 Default Login: admin / admin123`);
      console.log(`🗄️  Database: ${dbConfig.database}`);
      console.log(`⚖️  Features: Full CRUD, Price Override, Stock Tracking`);
      console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log('🐟 ================================\n');
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

// Reports Routes - Enhanced
app.get('/api/reports/dashboard', authenticateToken, async (req, res) => {
  try {
    const [productCount] = await pool.execute(
      'SELECT COUNT(*) as count FROM products WHERE is_active = TRUE'
    );
    const [customerCount] = await pool.execute(
      'SELECT COUNT(*) as count FROM customers WHERE is_active = TRUE'
    );
    const [transactionCount] = await pool.execute(
      'SELECT COUNT(*) as count FROM transactions WHERE DATE(created_at) = CURDATE()'
    );
    
    const [totalRevenue] = await pool.execute(
      'SELECT COALESCE(SUM(total), 0) as total FROM transactions WHERE status = "completed" AND DATE(created_at) = CURDATE()'
    );
    
    const [lowStock] = await pool.execute(
      'SELECT * FROM products WHERE stock_kg < min_stock_kg AND is_active = TRUE ORDER BY stock_kg ASC LIMIT 10'
    );
    
    const [recentTransactions] = await pool.execute(`
      SELECT t.total, t.actual_weight_kg, c.name as customer_name, p.name as product_name, t.created_at
      FROM transactions t 
      JOIN customers c ON t.customer_id = c.id 
      JOIN products p ON t.product_id = p.id 
      ORDER BY t.created_at DESC LIMIT 5
    `);

    const [totalStock] = await pool.execute(
      'SELECT COALESCE(SUM(stock_kg), 0) as total_kg FROM products WHERE is_active = TRUE'
    );

    res.json({
      totalProducts: productCount[0].count,
      totalCustomers: customerCount[0].count,
      totalTransactions: transactionCount[0].count,
      totalRevenue: parseFloat(totalRevenue[0].total),
      totalStockKg: parseFloat(totalStock[0].total_kg),
      lowStock,
      recentTransactions
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Stock movement logs
app.get('/api/stock-movements', authenticateToken, async (req, res) => {
  try {
    const [movements] = await pool.execute(`
      SELECT sm.*, p.name as product_name, p.code as product_code, u.username as created_by_name
      FROM stock_movements sm
      JOIN products p ON sm.product_id = p.id
      LEFT JOIN users u ON sm.created_by = u.id
      ORDER BY sm.created_at DESC
      LIMIT 100
    `);
    res.json(movements);
  } catch (error) {
    console.error('Stock movements error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
  });
});



// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🔄 Shutting down gracefully...');
  if (pool) {
    await pool.end();
    console.log('✅ Database connections closed');
  }
  process.exit(0);
});

// Start server
async function startServer() {
  try {
    await initializeDatabase();
    
    app.listen(PORT, () => {
      console.log('\n🐟 ================================');
      console.log('🚀 Enhanced Fish Distribution POS Started!');
      console.log(`📡 Server: http://localhost:${PORT}`);
      console.log(`🔑 Default Login: admin / admin123`);
      console.log(`🗄️  Database: ${dbConfig.database}`);
      console.log(`⚖️  Features: Full CRUD, Price Override, Stock Tracking`);
      console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log('🐟 ================================\n');
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

startServer();