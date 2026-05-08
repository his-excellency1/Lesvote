const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'data', 'db.json');

const db = JSON.parse(fs.readFileSync(DB_PATH));

// Hash super admin password
if (db.superAdmin && db.superAdmin.password && !db.superAdmin.password.startsWith('$2')) {
  console.log('Hashing super admin password...');
  db.superAdmin.password = bcrypt.hashSync(db.superAdmin.password, 10);
}

// Hash event admin passwords
if (db.eventAdmins && Array.isArray(db.eventAdmins)) {
  db.eventAdmins.forEach((admin, idx) => {
    if (admin.password && !admin.password.startsWith('$2')) {
      console.log(`Hashing password for admin: ${admin.username}`);
      admin.password = bcrypt.hashSync(admin.password, 10);
    }
  });
}

fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
console.log('✓ Database migration complete!');
