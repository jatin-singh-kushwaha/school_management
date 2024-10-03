const bcrypt = require('bcrypt');
const Admin = require('../models/adminSchema.js');
const Sclass = require('../models/sclassSchema.js');
const Student = require('../models/studentSchema.js');
const Teacher = require('../models/teacherSchema.js');
const Subject = require('../models/subjectSchema.js');
const Notice = require('../models/noticeSchema.js');
const Complain = require('../models/complainSchema.js');

// Admin registration with password hashing
const adminRegister = async (req, res) => {
    try {
        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPass = await bcrypt.hash(req.body.password, salt);

        const admin = new Admin({
            ...req.body,
            password: hashedPass
        });

        // Check if admin with same email or school name already exists
        const existingAdminByEmail = await Admin.findOne({ email: req.body.email });
        const existingSchool = await Admin.findOne({ schoolName: req.body.schoolName });

        if (existingAdminByEmail) {
            res.send({ message: 'Email already exists' });
        } else if (existingSchool) {
            res.send({ message: 'School name already exists' });
        } else {
            // Save the admin and return the result without the password
            let result = await admin.save();
            result.password = undefined; // Ensure password isn't sent back in the response
            res.send(result);
        }
    } catch (err) {
        res.status(500).json(err);
    }
};

// Admin login with secure password comparison
const adminLogIn = async (req, res) => {
    if (req.body.email && req.body.password) {
        let admin = await Admin.findOne({ email: req.body.email });
        if (admin) {
            // Compare the provided password with the hashed password in the database
            const validated = await bcrypt.compare(req.body.password, admin.password);
            if (validated) {
                admin.password = undefined; // Do not return the password in the response
                res.send(admin);
            } else {
                res.send({ message: "Invalid password" });
            }
        } else {
            res.send({ message: "User not found" });
        }
    } else {
        res.send({ message: "Email and password are required" });
    }
};

// Get admin details by ID with error handling
const getAdminDetail = async (req, res) => {
    try {
        let admin = await Admin.findById(req.params.id);
        if (admin) {
            admin.password = undefined; // Do not return the password in the response
            res.send(admin);
        } else {
            res.status(404).send({ message: "No admin found" });
        }
    } catch (err) {
        res.status(500).json({ message: "Error fetching admin details", error: err });
    }
};

module.exports = { adminRegister, adminLogIn, getAdminDetail };
