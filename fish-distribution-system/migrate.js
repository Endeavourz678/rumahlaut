// migrate.js - Database Migration Runner
const mysql = require('mysql2/promise');
require('dotenv').config();

async function runMigration() {
  const connection = await mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'fish_distribution',
    multipleStatements: true
  });

  console.log('🔄 Starting database migration...');

  try {
    // Migration SQL
    const migrationSQL = `
      -- Add missing columns to products table
      ALTER TABLE products 
      ADD COLUMN IF NOT EXISTS category VARCHAR(50) DEFAULT 'Ikan Segar' AFTER min_stock_kg,
      ADD COLUMN IF NOT EXISTS supplier VARCHAR(100) DEFAULT NULL AFTER category;

      -- Add missing columns to customers table
      ALTER TABLE customers 
      ADD COLUMN IF NOT EXISTS customer_type ENUM('retail', 'wholesale', 'restaurant') DEFAULT 'retail' AFTER shipping_cost,
      ADD COLUMN IF NOT EXISTS credit_limit DECIMAL(12,2) DEFAULT 0 AFTER customer_type;

      -- Add missing columns to transactions table
      ALTER TABLE transactions 
      ADD COLUMN IF NOT EXISTS transaction_no VARCHAR(50) AFTER id,
      ADD COLUMN IF NOT EXISTS original_price_per_kg DECIMAL(10,2) DEFAULT 0 AFTER price_per_kg,
      ADD COLUMN IF NOT EXISTS price_adjusted BOOLEAN DEFAULT FALSE AFTER original_price_per_kg,
      ADD COLUMN IF NOT EXISTS cashier_id INT AFTER weighed_by,
      ADD COLUMN IF NOT EXISTS discount_percent DECIMAL(5,2) DEFAULT 0 AFTER cashier_id,
      ADD COLUMN IF NOT EXISTS discount_amount DECIMAL(10,2) DEFAULT 0 AFTER discount_percent,
      ADD COLUMN IF NOT EXISTS tax_percent DECIMAL(5,2) DEFAULT 0 AFTER discount_amount,
      ADD COLUMN IF NOT EXISTS tax_amount DECIMAL(10,2) DEFAULT 0 AFTER tax_percent;

      -- Create stock_movements table if it doesn't exist
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
      );
    `;

    // Execute migration
    await connection.execute(migrationSQL);
    console.log('✅ Database structure updated');

    // Update existing data
    console.log('🔄 Updating existing data...');

    // Update products with default category
    await connection.execute("UPDATE products SET category = 'Ikan Segar' WHERE category IS NULL OR category = ''");
    console.log('✅ Updated products with default category');

    // Update customers with default type
    await connection.execute("UPDATE customers SET customer_type = 'retail' WHERE customer_type IS NULL OR customer_type = ''");
    console.log('✅ Updated customers with default type');

    // Update transactions with transaction numbers
    await connection.execute("UPDATE transactions SET transaction_no = CONCAT('TRX', id) WHERE transaction_no IS NULL OR transaction_no = ''");
    console.log('✅ Updated transactions with transaction numbers');

    // Update original prices
    await connection.execute(`
      UPDATE transactions t
      JOIN products p ON t.product_id = p.id
      SET t.original_price_per_kg = t.price_per_kg
      WHERE t.original_price_per_kg = 0 OR t.original_price_per_kg IS NULL
    `);
    console.log('✅ Updated transactions with original prices');

    // Add indexes for better performance
    try {
      await connection.execute('ALTER TABLE transactions ADD INDEX idx_transaction_no (transaction_no)');
      await connection.execute('ALTER TABLE transactions ADD INDEX idx_status (status)');
      await connection.execute('ALTER TABLE transactions ADD INDEX idx_date (transaction_date)');
      await connection.execute('ALTER TABLE products ADD INDEX idx_category (category)');
      await connection.execute('ALTER TABLE customers ADD INDEX idx_type (customer_type)');
      console.log('✅ Added database indexes');
    } catch (error) {
      if (error.code === 'ER_DUP_KEYNAME') {
        console.log('ℹ️  Indexes already exist, skipping...');
      } else {
        console.log('⚠️  Warning adding indexes:', error.message);
      }
    }

    console.log('\n🎉 Database migration completed successfully!');
    console.log('✅ All new columns added');
    console.log('✅ Existing data updated');
    console.log('✅ Indexes optimized');
    console.log('\n🚀 You can now restart your server with: npm run dev');

  } catch (error) {
    console.error('❌ Migration failed:', error.message);
    console.error('💡 Tip: Make sure your database is running and credentials are correct in .env');
    process.exit(1);
  } finally {
    await connection.end();
  }
}

// Run migration if this file is executed directly
if (require.main === module) {
  runMigration().catch(console.error);
}

module.exports = { runMigration };