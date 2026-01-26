const { query } = require('../config/postgres');

const Review = {
  async find(conditions = {}) {
    let sql = 'SELECT * FROM reviews';
    const values = [];
    
    if (Object.keys(conditions).length > 0) {
      const clauses = [];
      Object.keys(conditions).forEach(key => {
        values.push(conditions[key]);
        clauses.push(`${key} = $${values.length}`);
      });
      sql += ' WHERE ' + clauses.join(' AND ');
    }
    
    sql += ' ORDER BY created_at DESC LIMIT 200';
    const result = await query(sql, values);
    return result.rows.map(row => ({
      ...row,
      _id: row.id,
      created_at: row.created_at,
      timestamp: row.created_at
    }));
  },

  async create(reviewData) {
    const { name, email, message, rating, project_id, user_id } = reviewData;
    const result = await query(
      'INSERT INTO reviews (name, email, message, rating, project_id, user_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [name, email || null, message, rating, project_id || null, user_id || null]
    );
    return result.rows[0];
  }
};

module.exports = Review;
