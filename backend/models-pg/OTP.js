const { query } = require('../config/postgres');

const OTP = {
  async findOne(conditions) {
    let sql = 'SELECT * FROM otps WHERE ';
    const values = [];
    const clauses = [];

    Object.keys(conditions).forEach(key => {
      if (key === 'expiresAt' || key === 'expires_at') {
        if (conditions[key].$gt) {
          values.push(conditions[key].$gt);
          clauses.push(`expires_at > $${values.length}`);
        }
      } else if (key === 'createdAt' || key === 'created_at') {
        if (conditions[key].$gte) {
          values.push(conditions[key].$gte);
          clauses.push(`created_at >= $${values.length}`);
        }
      } else {
        values.push(conditions[key]);
        clauses.push(`${key} = $${values.length}`);
      }
    });

    sql += clauses.join(' AND ') + ' LIMIT 1';
    const result = await query(sql, values);
    return result.rows[0] || null;
  },

  async countDocuments(conditions) {
    let sql = 'SELECT COUNT(*) as count FROM otps WHERE ';
    const values = [];
    const clauses = [];

    Object.keys(conditions).forEach(key => {
      if (key === 'createdAt' || key === 'created_at') {
        if (conditions[key].$gte) {
          values.push(conditions[key].$gte);
          clauses.push(`created_at >= $${values.length}`);
        }
      } else {
        values.push(conditions[key]);
        clauses.push(`${key} = $${values.length}`);
      }
    });

    sql += clauses.join(' AND ');
    const result = await query(sql, values);
    return parseInt(result.rows[0].count, 10);
  },

  async create(otpData) {
    const { email, otp, type, expiresAt, expires_at } = otpData;
    const expiry = expiresAt || expires_at;
    const result = await query(
      'INSERT INTO otps (email, otp, type, expires_at) VALUES ($1, $2, $3, $4) RETURNING *',
      [email, otp, type || 'signup', expiry]
    );
    return result.rows[0];
  },

  async deleteMany(conditions) {
    let sql = 'DELETE FROM otps WHERE ';
    const values = [];
    const clauses = [];

    Object.keys(conditions).forEach(key => {
      values.push(conditions[key]);
      clauses.push(`${key} = $${values.length}`);
    });

    sql += clauses.join(' AND ');
    const result = await query(sql, values);
    return { deletedCount: result.rowCount };
  },

  async deleteOne(conditions) {
    let sql = 'DELETE FROM otps WHERE ';
    const values = [];
    const clauses = [];

    if (conditions._id || conditions.id) {
      values.push(conditions._id || conditions.id);
      clauses.push(`id = $${values.length}`);
    } else {
      Object.keys(conditions).forEach(key => {
        values.push(conditions[key]);
        clauses.push(`${key} = $${values.length}`);
      });
    }

    sql += clauses.join(' AND ');
    const result = await query(sql, values);
    return { deletedCount: result.rowCount };
  },

  async save(otp) {
    if (otp.id) {
      const result = await query(
        'UPDATE otps SET verified = $1, attempts = $2 WHERE id = $3 RETURNING *',
        [otp.verified, otp.attempts, otp.id]
      );
      return result.rows[0];
    }
    return this.create(otp);
  }
};

module.exports = OTP;
