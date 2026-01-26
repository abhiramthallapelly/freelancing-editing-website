const { query } = require('../config/postgres');

const Category = {
  async find() {
    const result = await query('SELECT * FROM categories ORDER BY name');
    return result.rows;
  },

  async findOne(conditions) {
    let sql = 'SELECT * FROM categories WHERE ';
    const values = [];
    const clauses = [];

    Object.keys(conditions).forEach(key => {
      values.push(conditions[key]);
      clauses.push(`${key} = $${values.length}`);
    });

    sql += clauses.join(' AND ') + ' LIMIT 1';
    const result = await query(sql, values);
    return result.rows[0] || null;
  },

  async findOneAndUpdate(conditions, data, options = {}) {
    const existing = await this.findOne(conditions);
    
    if (existing) {
      const setClauses = [];
      const values = [];
      
      Object.keys(data).forEach((key, idx) => {
        values.push(data[key]);
        setClauses.push(`${key} = $${idx + 1}`);
      });
      
      values.push(existing.id);
      const sql = `UPDATE categories SET ${setClauses.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE id = $${values.length} RETURNING *`;
      const result = await query(sql, values);
      return result.rows[0];
    } else if (options.upsert) {
      return this.create({ ...conditions, ...data });
    }
    return null;
  },

  async create(categoryData) {
    const { name, description, icon } = categoryData;
    const result = await query(
      'INSERT INTO categories (name, description, icon) VALUES ($1, $2, $3) RETURNING *',
      [name, description || null, icon || null]
    );
    return result.rows[0];
  }
};

module.exports = Category;
