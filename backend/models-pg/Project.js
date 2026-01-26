const { query } = require('../config/postgres');

const Project = {
  async find(conditions = {}) {
    let sql = 'SELECT * FROM projects';
    const values = [];
    
    if (Object.keys(conditions).length > 0) {
      const clauses = [];
      if (conditions.$or) {
        const orClauses = conditions.$or.map(cond => {
          return Object.keys(cond).map(key => {
            if (cond[key].$regex) {
              values.push(`%${cond[key].$regex}%`);
              return `${key} ILIKE $${values.length}`;
            }
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
      sql += ' WHERE ' + clauses.join(' AND ');
    }
    
    sql += ' ORDER BY created_at DESC';
    const result = await query(sql, values);
    return result.rows;
  },

  async findById(id) {
    const result = await query('SELECT * FROM projects WHERE id = $1', [id]);
    const row = result.rows[0];
    if (row) {
      row._id = row.id;
    }
    return row || null;
  },

  async findOne(conditions) {
    const results = await this.find(conditions);
    return results[0] || null;
  },

  async create(projectData) {
    const { title, description, file_path, image_path, is_free, price, category, file_type, file_size } = projectData;
    const result = await query(
      `INSERT INTO projects (title, description, file_path, image_path, is_free, price, category, file_type, file_size)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [title, description, file_path, image_path || null, is_free !== undefined ? is_free : true, price || 0, category || 'template', file_type || null, file_size || null]
    );
    return result.rows[0];
  },

  async findByIdAndUpdate(id, updates, options = {}) {
    const setClauses = [];
    const values = [];
    
    Object.keys(updates).forEach((key, idx) => {
      if (key !== 'id' && key !== '_id') {
        values.push(updates[key]);
        setClauses.push(`${key} = $${idx + 1}`);
      }
    });
    
    values.push(id);
    const sql = `UPDATE projects SET ${setClauses.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE id = $${values.length} RETURNING *`;
    const result = await query(sql, values);
    return result.rows[0] || null;
  },

  async findByIdAndDelete(id) {
    const result = await query('DELETE FROM projects WHERE id = $1 RETURNING *', [id]);
    return result.rows[0] || null;
  },

  async incrementDownload(id) {
    const result = await query(
      'UPDATE projects SET download_count = download_count + 1 WHERE id = $1 RETURNING *',
      [id]
    );
    return result.rows[0];
  },

  async incrementView(id) {
    const result = await query(
      'UPDATE projects SET view_count = view_count + 1 WHERE id = $1 RETURNING *',
      [id]
    );
    return result.rows[0];
  }
};

module.exports = Project;
