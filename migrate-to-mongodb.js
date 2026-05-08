require('dotenv').config();
const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH = path.join(__dirname, 'data', 'db.json');
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/lesvote';

// Schemas
const superAdminSchema = new mongoose.Schema({
  username: String,
  password: String
}, { collection: 'superAdmin' });

const eventAdminSchema = new mongoose.Schema({
  id: { type: Number, unique: true },
  username: String,
  password: String,
  events: [Number]
}, { collection: 'eventAdmins' });

const categorySchema = new mongoose.Schema({
  id: Number,
  name: String,
  icon: String
});

const nomineeSchema = new mongoose.Schema({
  id: Number,
  name: String,
  catId: Number,
  photo: String,
  votes: { type: Number, default: 0 }
});

const transactionSchema = new mongoose.Schema({
  id: mongoose.Schema.Types.Mixed,
  nomineeId: Number,
  nomName: String,
  catName: String,
  votes: Number,
  amt: Number,
  qty: Number,
  phone: String,
  name: String,
  method: String,
  time: Date,
  status: String
});

const eventSchema = new mongoose.Schema({
  id: { type: Number, unique: true },
  name: String,
  desc: String,
  icon: String,
  photo: String,
  votingOpen: { type: Boolean, default: true },
  votePrice: { type: Number, default: 0.5 },
  showResults: { type: Boolean, default: true },
  categories: [categorySchema],
  nominees: [nomineeSchema],
  transactions: [transactionSchema],
  blocked: [String]
}, { collection: 'events' });

const paystackConfigSchema = new mongoose.Schema({
  publicKey: String
}, { collection: 'paystackConfig' });

// Models
const SuperAdmin = mongoose.model('SuperAdmin', superAdminSchema);
const EventAdmin = mongoose.model('EventAdmin', eventAdminSchema);
const Event = mongoose.model('Event', eventSchema);
const PaystackConfig = mongoose.model('PaystackConfig', paystackConfigSchema);

async function migrate() {
  try {
    console.log('Connecting to MongoDB...');
    await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log('✓ Connected to MongoDB');

    // Clear existing collections
    console.log('Clearing existing collections...');
    await SuperAdmin.deleteMany({});
    await EventAdmin.deleteMany({});
    await Event.deleteMany({});
    await PaystackConfig.deleteMany({});
    console.log('✓ Collections cleared');

    // Read JSON file
    if (!fs.existsSync(DB_PATH)) {
      console.log('No db.json file found. Creating initial data...');
      await initializeDB();
      return;
    }

    const db = JSON.parse(fs.readFileSync(DB_PATH));
    console.log('✓ Read db.json file');

    // Migrate super admin
    if (db.superAdmin) {
      const superAdmin = new SuperAdmin({
        username: db.superAdmin.username,
        password: db.superAdmin.password // Already hashed
      });
      await superAdmin.save();
      console.log(`✓ Migrated super admin: ${db.superAdmin.username}`);
    }

    // Migrate event admins
    if (db.eventAdmins && Array.isArray(db.eventAdmins)) {
      for (const admin of db.eventAdmins) {
        const eventAdmin = new EventAdmin({
          id: admin.id,
          username: admin.username,
          password: admin.password, // Already hashed
          events: admin.events || []
        });
        await eventAdmin.save();
      }
      console.log(`✓ Migrated ${db.eventAdmins.length} event admins`);
    }

    // Migrate events
    if (db.events && Array.isArray(db.events)) {
      for (const evt of db.events) {
        const event = new Event({
          id: evt.id,
          name: evt.name,
          desc: evt.desc,
          icon: evt.icon,
          photo: evt.photo,
          votingOpen: evt.votingOpen !== undefined ? evt.votingOpen : (evt.open !== undefined ? evt.open : true),
          votePrice: evt.votePrice || 0.5,
          showResults: evt.showResults !== undefined ? evt.showResults : true,
          categories: evt.categories || [],
          nominees: evt.nominees || [],
          transactions: evt.transactions || [],
          blocked: evt.blocked || []
        });
        await event.save();
      }
      console.log(`✓ Migrated ${db.events.length} events with all data`);
    }

    // Migrate paystack config
    if (db.paystack) {
      const config = new PaystackConfig({
        publicKey: db.paystack.publicKey || ''
      });
      await config.save();
      console.log('✓ Migrated Paystack config');
    }

    console.log('\n✅ Migration completed successfully!');
    console.log('Your data has been migrated from db.json to MongoDB.');
    console.log('\nNext steps:');
    console.log('1. Verify your data in MongoDB');
    console.log('2. Back up your db.json file (it is no longer used)');
    console.log('3. Restart the server with: npm start');

    process.exit(0);
  } catch (error) {
    console.error('❌ Migration error:', error.message);
    process.exit(1);
  }
}

async function initializeDB() {
  try {
    const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'awards2025', 10);
    
    const superAdmin = new SuperAdmin({
      username: process.env.ADMIN_USERNAME || 'admin',
      password: hashedPassword
    });
    await superAdmin.save();
    console.log('✓ Created initial super admin');

    const config = new PaystackConfig({
      publicKey: process.env.PAYSTACK_PUBLIC_KEY || ''
    });
    await config.save();
    console.log('✓ Created Paystack config');

    console.log('\n✅ Initial MongoDB database created!');
    process.exit(0);
  } catch (error) {
    console.error('❌ Initialization error:', error.message);
    process.exit(1);
  }
}

migrate();
