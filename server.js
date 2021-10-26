const dotenv = require('dotenv').config();
const express = require('express');
const app = express();
const cors = require('cors');
const port = 3500;
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require("bcrypt");
const db = require('./Database/dbQueries');
const fs = require('fs');
const https = require('https');

var key = fs.readFileSync('selfsigned.key');
var cert = fs.readFileSync('selfsigned.crt');


var options = {
  key: key,
  cert: cert
};

app.use(cors());

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.get('/', async (req, res) => {
    res.send({message:'welcome to the server'});
});


//complaint end-points
app.post('/api/submitComplaint',verify, async (req, res) => {
  if(!req.body.token) {
    res.send({status: "user not logged in"});
  }
  if(!req.body.complaint.centreLocation || !req.body.complaint.centreLocation || !req.body.complaint.incidentType || !req.body.complaint.dateOfComp || !req.body.complaint.compDetails || !req.body.complaint.desiredOutcome){
    return res.send({status: "failed to report. Please fill all fields"})
  }

  try {
    const userID = jwt.verify(req.body.token, process.env.ACCESS_SECRET);
    complaint = req.body.complaint;
    complaint.userId = userID._id;
    delete complaint.token;
    db.reportIncident(complaint);
    console.log(complaint);
    res.send({status: "incident reported"});
  } catch (error) {
    console.log(error);
    res.send({
      description: "access token invalid",
      verification: false
    });
  }
});

app.post('/fetchComplaints',verify, async (req, res) => {
  console.log(req.body);
  complaints = await db.userIncidents({userId: req.body.user._id});
  console.log(complaints);
  res.send(complaints);
});
app.post('/fetchComplaint',verify, async (req, res) => {
  try {
    console.log(req.body);
    complaint = await db.userIncident(req.body.user._id, req.body.complaintId);
    console.log(complaint);
    res.send(complaint);
  } catch (error) {
    console.log(error);
    res.send({status: error})
  }
});
app.post('/deleteComplaint',verify, async (req, res) => {
  const userID = jwt.verify(req.body.token, process.env.ACCESS_SECRET);
  if (userID.admin) {
    complaint = await db.AdminDeleteIncident(req.body.complaintId);
  } else {
    complaint = await db.deleteIncident(req.body.complaintId, req.body.user._id);
  }
  if(complaint.deletedCount == 1) res.send({status: "report deleted", return: complaint});
  if(complaint.deletedCount != 1) res.send({status: "report not deleted. Please try again"})
});
app.post('/updateComplaint',verify, async (req, res) => {
  try {
    if(req.body.user.admin){
      console.log("yesyesytes" ,req.body.id);
      update = await db.updateIncident({ _id: req.body.id }, req.body.update);
    }else{
      update = await db.updateIncident({
        userId: req.body.user._id,
        _id: req.body.id
      }, req.body.update);
  
    }
    console.log(update);
    if(update.modifiedCount == 1) res.send({status: "updated incident successfully"});
    if(update.modifiedCount != 1) res.send({status: "did not update"})
  } catch (error) {
    console.log(error);
    res.send({status: "error updating incident"})
  }
});

//user end-points
app.post('/login', async (req,res) => {
  console.log(req.body);
  //data validation
  if(!req.body.email) return res.send({status: "email field empty"});
  if(!req.body.password) return res.send({status: "password field empty"});

  //fetch user
  const user = await db.findUserByEmail(req.body.email);

  //check if user is found
  if(user == null){
    res.send({status: "Incorrect credentials"});

  }else{
    //check if password is valid
    const password = await bcrypt.compare(req.body.password, await user.password)
    if(!password) return res.send({status: "access denied (incorrect password)"});

    //create access token
    const accessToken = jwt.sign(
      {
        _id: user._id,
        admin: user.admin
      },
      process.env.ACCESS_SECRET,
      { expiresIn: '3h' });

    //send a welcome back with token id
    res.send({
      status: "success",
      AT: accessToken
    })
  }

})
app.post('/register', async (req,res) => {

  //data validation
  if(!req.body.fName) return res.send({status: "first name field empty"});
  if(!req.body.lName) return res.send({status: "last name field empty"});
  if(!req.body.email) return res.send({status: "email field empty"});
  if(!req.body.password) return res.send({status: "password field empty"});

  try {
    //check if email exists
    const userEmail = await db.findUserByEmail(req.body.email);

    if(userEmail) return res.send({status: "email exists: " + userEmail.email});

  } catch (error) {
    res.send({status: "error checking email", error: error})
  }

  //hash user password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.password, salt)
  req.body.password = hashedPassword;
  try {
    //add user to mongoDB
    db.addUser(req.body);
    res.send({status: `added user`});
  } catch (error) {
    console.log(error);
    res.send({status: `error registering user`});
  }
})
app.post('/registerStaff', async (req,res) => {

  //data validation
  if(!req.body.fName) return res.send({status: "first name field empty"});
  if(!req.body.lName) return res.send({status: "last name field empty"});
  if(!req.body.eid) return res.send({status: "employee id field is empty"})
  if(!req.body.email) return res.send({status: "email field empty"});
  if(!req.body.password) return res.send({status: "password field empty"});

  try {
    //check if email exists
    const userEmail = await db.findUserByEmail(req.body.email);

    if(userEmail) return res.send({status: "email exists: " + userEmail.email});

  } catch (error) {
    res.send({status: "error checking email", error: error})
  }
  try {
    //check if employee ID exists
    const employeeDetails = await db.findID(req.body.eid);
    console.log(employeeDetails)
    if(!employeeDetails) return res.send({status: "employee ID is incorrect"})

  } catch (error) {
    console.log(error);
    res.send({status: "error checking employee id", error: error})
  }

  //hash user password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.password, salt)
  req.body.password = hashedPassword;
  try {
    //add user to mongoDB
    db.addUser(req.body);
    res.send({status: `added user`});
  } catch (error) {
    console.log(error);
    res.send({status: `error registering user`});
  }
})
app.post('/findUser',verify, async (req,res) => {
  //find user
  try {
    user = await db.findUser(req.body.user._id);
    res.send(user);
  } catch (error) {
    res.send({status: "user not found"})
  }
})

app.post('/findUserAdmin',verifyAdmin, async (req,res) => {
  //find user
  try {
    user = await db.findUser(req.body._id);
    res.send(user);
  } catch (error) {
    res.send({status: "user not found"})
  }
})

app.post('/deleteUser',verify, async (req, res) => {
  employee = await db.deleteUser(req.body.user._id);

  if(employee.deletedCount == 1){
    res.send({status: "user deleted"});
  }
  if(employee.deletedCount != 1) res.send({status: "user not deleted. Please try again"})
});

app.post('/deleteUserAdmin',verifyAdmin, async (req, res) => {
  employee = await db.deleteUser(req.body._id);

  if(employee.deletedCount == 1){
    res.send({status: "user deleted"});
  }
  if(employee.deletedCount != 1) res.send({status: "user not deleted. Please try again"})
});

app.post('/updateUser',verify, async (req, res) => {
  try {
    update = await db.updateUser(req.body.user._id, req.body.update);
    console.log(update);
    res.send({status: "updated user records"});
  } catch (error) {
    console.log(error);
    res.send({status: "error updating user"})
  }
});

app.post('/updateUserAdmin',verifyAdmin, async (req, res) => {
  try {
    update = await db.updateUser(req.body._id, req.body.update);
    console.log(update);
    res.send({status: "updated user records"});
  } catch (error) {
    console.log(error);
    res.send({status: "error updating user"})
  }
});

app.post('/updateUserPassword',verify, async (req, res) => {
  console.log(req.body);
  //hash user password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.password, salt)
  req.body.password = hashedPassword;

  try {
    update = await db.updateUser(req.body.user._id, {password: req.body.password});
    console.log(update);
    res.send({status: "updated user records"});
  } catch (error) {
    console.log(error);
    res.send({status: "error updating user"})
  }
});

//admin end-points

app.post('/registerAdmin',verifyAdmin, async (req,res) => {
  //data validation
  if(!req.body.newUser.email) return res.send({status: "email field empty"});
  if(!req.body.newUser.password) return res.send({status: "password field empty"});

  //check if email exists
  userEmail = await db.findUserByEmail(req.body.newUser.email);
  if(userEmail) return res.send({status: "email exists: " + userEmail.email});

  //hash user password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.newUser.password, salt)
  req.body.newUser.password = hashedPassword;

  try {
    //add user to mongoDB
    db.addUserAdmin(req.body.newUser);
    res.send({status: "added user successfully"});
  } catch (error) {
    res.send({status: "error adding user"})
  }
})
app.post('/addEmployee',verifyAdmin, async (req,res) => {
  //data validation
  if(!req.body.eid) return res.send({status: "employee id field is empty"});
  if(!req.body.fName) return res.send({status: "first name field is empty"});
  if(!req.body.lName) return res.send({status: "last name field is empty"});
  if(!req.body.storeId) return res.send({status: "store field is empty"});
  if(!req.body.centreId) return res.send({status: "centre field is empty"});

  //check if ID exists
  //user = await db.findID(req.body.eid);
  //if(user) return res.send({status: "employee exists: " + user.eid});

  try {
    //add user to mongoDB
    db.addID(req.body);
    res.send({status: `added employee ID`});
  } catch (error) {
    res.send({status: error});
  }
})
app.post('/findEmployee',verifyAdmin, async (req, res) => {
  try {
    employee = await db.findID(req.body.eid);
    console.log(employee);
    res.send(employee);
  } catch (error) {
    console.log(error);
    res.send({status: error})
  }
});
app.post('/findAllEmployees',verifyAdmin, async (req, res) => {
  try {
    employee = await db.findAllID();
    res.send(employee);
  } catch (error) {
    console.log(error);
    res.send({status: error})
  }
});
app.post('/deleteEmployee',verifyAdmin, async (req, res) => {
  employee = await db.deleteID(req.body.eid);
  console.log(employee);
  if(employee.deletedCount == 1) res.send({status: "report deleted", return: employee});
  if(employee.deletedCount != 1) res.send({status: "report not deleted. Please try again"})
});
app.post('/updateEmployee',verifyAdmin, async (req, res) => {
  try {
    update = await db.updateID(req.body.eid, req.body.update);
    console.log(update);
    res.send({status: "updated employee records"});
  } catch (error) {
    console.log(error);
    res.send({status: "error updating employee"})
  }
});
app.post('/findAllUsers',verifyAdmin, async (req,res) => {
  //find all user
  try {
    user = await db.findAllUsers();
    res.send(user);
  } catch (error) {
    res.send({status: "error fetching users"})
  }
})
app.post('/allComplaints',verifyAdmin, async (req,res) => {
  complaints = await db.allIncidents();

  res.send(complaints);
})
app.post('/findAllOffenders',verify, async (req,res) => {
  offenders = await db.getAllOffenders();

  res.send(offenders);
})
app.post('/createOffender',verify, async (req,res) => {
  //Ensure we have all fields we need
  if(!req.body.offender.fName || !req.body.offender.lName) return res.send({status: "name field empty"});
  if(!req.body.offender.description) return res.send({status: "description field empty"});

  console.log(req.body);
  
  //If all Fields are good attempt to add user to datebase
  try {
    //add user to mongoDB
    const OID = await db.addOffender(req.body.offender);
    console.log(OID);
    res.send({status: `added offender`, offenderId: OID});
  } catch (error) {
    console.log(error);
    res.send({status: `error creating offender`});
  }
})

//store admin end-points
app.post('/allStores',verify, async (req,res) => {
  stores = await db.getAllStores();
  console.log("fetching stores");
  res.send(stores);
})
app.post('/addStore',verifyAdmin, async (req,res) => {
  try {
    add = await db.addStore(req.body.store);
    console.log(add);
    if(add.modifiedCount == 1) res.send({status: "Added store successfully"});
    if(add.modifiedCount != 1) res.send({status: "Could not add store"});
  } catch (error) {
    console.log(error);
    res.send({status: "error adding store"})
  }
})

app.post('/deleteStore',verifyAdmin, async (req,res) => {
  del = await db.deleteStore(req.body.store);
  if(del.modifiedCount == 1) res.send({status: "Store deleted", return: del});
  if(del.modifiedCount != 1) res.send({status: "Store not deleted. Please try again"})
  }
)

app.post('/addCentre',verifyAdmin, async (req,res) => {
  try {
    add = await db.addCentre(req.body.centre);
    console.log(add);
    if (add.insertedId) res.send({status: "Added centre successfully"});
    if (!add.insertedId) res.send({status: "Could not add centre"});
  } catch (error) {
    console.log(error);
    res.send({status: "Could not add centre"});
  }
})

app.post('/deleteCentre',verifyAdmin, async (req,res) => {
  try {
  del = await db.deleteCentre(req.body.centre);
  console.log(del);
  if(del.deletedCount == 1) res.send({status: "Centre deleted", return: del});
  if(del.deletedCount != 1) res.send({status: "Centre not deleted. Please try again"})
  } catch (error) {
    console.log(error);
      res.send("Centre not deleted!");
  }
  }
)

//verify end-points
function verify(req,res,next) {
  console.log("verify user")
  const token = req.body.token;
  if(!token) return res.send('Access Denied no access token: '+ token);
  try {
      const user = jwt.verify(token, process.env.ACCESS_SECRET);
      req.body.user = user;
      next();
  } catch (error) {
    console.log(error);
      res.send("access token invalid");
  }
}
function verifyAdmin(req,res,next) {
  console.log("verify Admin")
  const token = req.body.token;
  if(!token) return res.send({status: 'Access Denied no access token: '+ token});
  try {
      const user = jwt.verify(token, process.env.ACCESS_SECRET);
      req.body.user = user;
      if(!user.admin) res.send({status: "access token invalid"});
      if(user.admin) next();

  } catch (error) {
    console.log(error);
      res.send({status: "access token invalid"});
  }
}
app.post('/verify', async (req,res) => {
  const token = req.body.token;

  if(!token){
    return res.send(
    {
      description: 'Access Denied no access token: '+ token,
      verification: false
    });
  }

  try {
    const user = jwt.verify(token, process.env.ACCESS_SECRET);
    res.send({verification: true, admin: user.admin});
  } catch (error) {
    console.log(error);
    res.send({
      description: "access token invalid",
      verification: false,
      admin: false
    });
  }
})

app.post('/getAllUsers', verifyAdmin, async (req, res) => {
  users = await db.getAllUsers();
  res.send(users);
})

const server = https.createServer(options, app);

server.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})
