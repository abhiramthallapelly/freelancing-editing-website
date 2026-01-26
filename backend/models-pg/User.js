const { query } = require('../config/postgres');
const bcrypt = require('bcryptjs');

const User = {
  async findOne(conditions) {
    let sql = 'SELECT * FROM users WHERE ';
    const values = [];
    const clauses = [];

    if (conditions.$or) {
      const orClauses = conditions.$or.map((cond, idx) => {
        const keys = Object.keys(cond);
        return keys.map(key => {
          values.push(cond[key]);
          return `${key} = $${values.length}`;
        }).join(' AND ');
      });
      clauses.push(`(${orClauses.join(' OR ')})`);
    } else {
      Object.keys(conditions).forEach(key => {
        values.push(conditions[key]);
        clauses.push(`${key} = $${values.length}`);
      });
    }

    sql += clauses.join(' AND ') + ' LIMIT 1';
    const result = await query(sql, values);
    return result.rows[0] || null;
  },

  async findById(id) {
    const result = await query('SELECT * FROM users WHERE id = $1', [id]);
    return result.rows[0] || null;
  },

  async create(userData) {
    const { username, email, password, full_name, auth_provider, google_id, facebook_id, instagram_id, profile_picture, is_verified } = userData;
    const result = await query(
      `INSERT INTO users (username, email, password, full_name, auth_provider, google_id, facebook_id, instagram_id, profile_picture, is_verified)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
      [username, email, password, full_name || null, auth_provider || 'local', google_id || null, facebook_id || null, instagram_id || null, profile_picture || null, is_verified || false]
    );
    return result.rows[0];
  },

  async findByIdAndUpdate(id, updates, options = {}) {
    const setClauses = [];
    const values = [];
    
    Object.keys(updates).forEach((key, idx) => {
      values.push(updates[key]);
      setClauses.push(`${key} = $${idx + 1}`);
    });
    
    values.push(id);
    const sql = `UPDATE users SET ${setClauses.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE id = $${values.length} RETURNING *`;
    const result = await query(sql, values);
    return result.rows[0] || null;
  },

  async save(user) {
    if (user.id) {
      const { id, ...updates } = user;
      return this.findByIdAndUpdate(id, updates);
    }
    return this.create(user);
  },

  async updateLastLogin(id) {
    const result = await query(
      'UPDATE users SET last_login = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *',
      [id]
    );
    return result.rows[0];
  }
};

module.exports = User;
