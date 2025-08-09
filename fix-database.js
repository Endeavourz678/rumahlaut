// fix-database.js - Script untuk memperbaiki struktur database
const mysql = require('mysql2/promise');
require('dotenv').config();

async function fixDatabase() {
  const connection = await mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'fish_distribution',
    multipleStatements: true
  });

  console.log('🔧 Fixing database structure...');

  try {
    // Fix transactions table
    console.log('📋 Checking transactions table...');
    
    // Add missing columns if not exists
    const fixTransactionsSQL = `
      -- Add transaction_no if missing
      SET @dbname = DATABASE();
      SET @tablename = 'transactions';
      SET @columnname = 'transaction_no';
      SET @preparedStatement = (SELECT IF(
        (
          SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
          WHERE table_name = @tablename
          AND table_schema = @dbname
          AND column_name = @columnname
        ) > 0,
        'SELECT 1',
        CONCAT('ALTER TABLE ', @tablename, ' ADD COLUMN ', @columnname, ' VARCHAR(50) AFTER id')
      ));
      PREPARE alterIfNotExists FROM @preparedStatement;
      EXECUTE alterIfNotExists;
      DEALLOCATE PREPARE alterIfNotExists;

      -- Update empty transaction numbers
      UPDATE transactions 
      SET transaction_no = CONCAT('TRX', YEAR(created_at), 
          LPAD(MONTH(created_at), 2, '0'), 
          LPAD(DAY(created_at), 2, '0'),
          LPAD(HOUR(created_at), 2, '0'),
          LPAD(MINUTE(created_at), 2, '0'),
          LPAD(SECOND(created_at), 2, '0'),
          LPAD(id, 4, '0'))
      WHERE transaction_no IS NULL OR transaction_no = '';

      -- Ensure transaction_date and transaction_time are set
      UPDATE transactions 
      SET transaction_date = DATE(created_at)
      WHERE transaction_date IS NULL;

      UPDATE transactions 
      SET transaction_time = TIME(created_at)  
      WHERE transaction_time IS NULL;
    `;

    await connection.execute(fixTransactionsSQL);
    console.log('✅ Fixed transactions table');

    // Check indexes
    console.log('📋 Checking indexes...');
    try {
      await connection.execute('CREATE INDEX idx_trans_date ON transactions(transaction_date)');
      console.log('✅ Created transaction_date index');
    } catch (e) {
      if (e.code !== 'ER_DUP_KEYNAME') throw e;
    }

    try {
      await connection.execute('CREATE INDEX idx_trans_status ON transactions(status)');
      console.log('✅ Created status index');
    } catch (e) {
      if (e.code !== 'ER_DUP_KEYNAME') throw e;
    }

    // Verify data integrity
    console.log('📋 Verifying data integrity...');
    
    const [orphanedTransactions] = await connection.execute(`
      SELECT COUNT(*) as count FROM transactions t
      LEFT JOIN customers c ON t.customer_id = c.id
      LEFT JOIN products p ON t.product_id = p.id
      WHERE c.id IS NULL OR p.id IS NULL
    `);
    
    if (orphanedTransactions[0].count > 0) {
      console.log(`⚠️  Found ${orphanedTransactions[0].count} orphaned transactions`);
      
      // Fix by setting status to cancelled
      await connection.execute(`
        UPDATE transactions t
        LEFT JOIN customers c ON t.customer_id = c.id
        LEFT JOIN products p ON t.product_id = p.id
        SET t.status = 'cancelled'
        WHERE c.id IS NULL OR p.id IS NULL
      `);
      console.log('✅ Fixed orphaned transactions');
    }

    // Add sample transaction if none exist
    const [transCount] = await connection.execute('SELECT COUNT(*) as count FROM transactions');
    if (transCount[0].count === 0) {
      console.log('📋 Adding sample transaction...');
      
      const [customers] = await connection.execute('SELECT id FROM customers WHERE is_active = TRUE LIMIT 1');
      const [products] = await connection.execute('SELECT id, price_per_kg_sell FROM products WHERE is_active = TRUE AND stock_kg > 5 LIMIT 1');
      
      if (customers.length > 0 && products.length > 0) {
        const customerId = customers[0].id;
        const productId = products[0].id;
        const pricePerKg = products[0].price_per_kg_sell;
        const weight = 2.5;
        const subtotal = weight * pricePerKg;
        const total = subtotal + 10000; // with shipping
        
        await connection.execute(`
          INSERT INTO transactions 
          (transaction_no, customer_id, product_id, actual_weight_kg, price_per_kg, 
           original_price_per_kg, subtotal, shipping_cost, total, payment_method, 
           status, transaction_date, transaction_time, weighed_by)
          VALUES 
          (?, ?, ?, ?, ?, ?, ?, ?, ?, 'cash', 'completed', CURDATE(), CURTIME(), 'Admin')
        `, [`TRX${Date.now()}`, customerId, productId, weight, pricePerKg, pricePerKg, subtotal, 10000, total]);
        
        console.log('✅ Added sample transaction');
      }
    }

    // Show final statistics
    const [stats] = await connection.execute(`
      SELECT 
        (SELECT COUNT(*) FROM products WHERE is_active = TRUE) as products,
        (SELECT COUNT(*) FROM customers WHERE is_active = TRUE) as customers,
        (SELECT COUNT(*) FROM transactions) as transactions,
        (SELECT COUNT(*) FROM users) as users
    `);
    
    console.log('\n📊 Database Statistics:');
    console.log(`   Products: ${stats[0].products}`);
    console.log(`   Customers: ${stats[0].customers}`);
    console.log(`   Transactions: ${stats[0].transactions}`);
    console.log(`   Users: ${stats[0].users}`);
    
    console.log('\n✅ Database fixed successfully!');
    console.log('🚀 You can now restart your server');

  } catch (error) {
    console.error('❌ Error fixing database:', error);
    throw error;
  } finally {
    await connection.end();
  }
}

// Run if called directly
if (require.main === module) {
  fixDatabase().catch(console.error);
}

module.exports = { fixDatabase };