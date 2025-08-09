const mysql = require('mysql2/promise');
require('dotenv').config();

async function testConnection() {
  try {
    const connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'fish_distribution'
    });
    
    console.log('✅ Connected to database');
    
    const [tables] = await connection.execute('SHOW TABLES');
    console.log('📋 Tables:', tables);
    
    const [count] = await connection.execute('SELECT COUNT(*) as count FROM transactions');
    console.log('📊 Transaction count:', count[0].count);
    
    await connection.end();
  } catch (error) {
    console.error('❌ Error:', error.message);
  }
}

testConnection();