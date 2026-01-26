const { query } = require('../config/postgres');

const Contact = {
  async create(contactData) {
    const { name, email, subject, message } = contactData;
    const result = await query(
      'INSERT INTO contacts (name, email, subject, message) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, email, subject || null, message]
    );
    return result.rows[0];
  },

  async find(conditions = {}) {
    let sql = 'SELECT * FROM contacts';
    const values = [];
    
    if (Object.keys(conditions).length > 0) {
      const clauses = [];
      Object.keys(conditions).forEach(key => {
        values.push(conditions[key]);
        clauses.push(`${key} = $${values.length}`);
      });
      sql += ' WHERE ' + clauses.join(' AND ');
    }
    
    sql += ' ORDER BY created_at DESC';
    const result = await query(sql, values);
    return result.rows;
  }
};

module.exports = Contact;
