const connection = require('./dbConnection');
const connect = connection.connect;
const disconnect = connection.disconnect;
const getMongoClient = connection.getMongoClient;

var ObjectId = require('mongodb').ObjectId;


//user queries
async function getAllUsers() {
    //connect to db
    let client = getMongoClient();
    await connect(client);

    //query DB. Fetch all users
    let usersList = await client.db('ASDdata').collection('Users').find().toArray();

    //disconnect and return
    await disconnect(client);
    return usersList;

}
async function findUser(user){
    //connect to db
    let client = getMongoClient();
    await connect(client);
    try {
        //query DB. Fetch users
        const fetchedUser = await client.db("ASDdata").collection("Users").findOne({_id: ObjectId(user)});
        return fetchedUser;
    } catch (error) {
        console.log(error);
        return false;
    }
}
async function findUserByEmail(user){
    //connect to db
    let client = getMongoClient();
    await connect(client);
    try {
        //query DB. Fetch users
        const fetchedUser = await client.db("ASDdata").collection("Users").findOne({email: user});
        return fetchedUser;
    } catch (error) {
        console.log(error);
        return false;
    }
}
async function addUser(newUser) {
    //connect to db
    let client = getMongoClient();
    await connect(client);

    //query DB. add user
    const user = await client.db("ASDdata").collection("Users").insertOne(newUser);
    console.log("new user added: ", user);
}
async function addUserAdmin(newUser) {
    //connect to db
    let client = getMongoClient();
    await connect(client);

    if(newUser.admin == true) newUser.admin = true;
    if(!newUser.admin || newUser.admin == "") newUser.admin = false;

    try {
        //query DB. add user
        const user = await client.db("ASDdata").collection("Users").insertOne(newUser);
        console.log("new user added: ", user);
    } catch (error) {
        console.log("error from dbqueries: ", error)
    }
}
async function updateUser(user, update){
    //connect to db
    let client = getMongoClient();
    await connect(client);

    //query DB. update
    const updateUser = await client.db("ASDdata").collection("Users").updateOne(
        { _id: ObjectId(user) },
        { $set: update });

    return updateUser;
}
async function deleteUser(user) {
    //connect to db
    let client = getMongoClient();
    await connect(client);

    //query DB. delete
    const fetchedIncidents = await client.db("ASDdata").collection("Users").deleteOne({_id: ObjectId(user)});
    return fetchedIncidents;
}

//incident queries
async function reportIncident(incident){
    //connect to db
    let client = getMongoClient();
    await connect(client);

    //query DB. add incident report
    const report = await client.db("ASDdata").collection("Complaints").insertOne(incident);
    console.log("new report added: ", report);
}
async function userIncidents(account){
    //connect to db
    let client = getMongoClient();
    await connect(client);
    console.log("ACCOUNT NUMBER: ", account)
    //query DB. add incident report
    const fetchedIncidents = await client.db("ASDdata").collection("Complaints").find(account).toArray();
    return fetchedIncidents;
}
async function userIncident(account,CID){
    //connect to db
    let client = getMongoClient();
    await connect(client);
    console.log("ACCOUNT NUMBER: ", account)
    //query DB. add incident report
    const fetchedIncident = await client.db("ASDdata").collection("Complaints").findOne({_id: ObjectId(CID)});
    return fetchedIncident;
}
async function updateIncident(incident, update){
    var updateIncident;

    //connect to db
    let client = getMongoClient();
    await connect(client);

    console.log(incident);
    //query DB. add incident report

    if(!incident.userId){
        updateIncident = await client.db("ASDdata").collection("Complaints").updateOne(
            { _id: ObjectId(incident._id) }, { $set: update });
    }else{
        updateIncident = await client.db("ASDdata").collection("Complaints").updateOne(
            { _id: ObjectId(incident._id), userId: incident.userId },
            { $set: update });
    }

    return updateIncident;
}
async function deleteIncident(incidentID, userID) {
    //connect to db
    let client = getMongoClient();
    await connect(client);

    //query DB. add incident report
    const fetchedIncidents = await client.db("ASDdata").collection("Complaints").deleteOne({_id: ObjectId(incidentID), userId: userID});
    return fetchedIncidents;
}
async function AdminDeleteIncident(incidentID) {
    //connect to db
    let client = getMongoClient();
    await connect(client);

    //query DB. add incident report
    const fetchedIncidents = await client.db("ASDdata").collection("Complaints").deleteOne({_id: ObjectId(incidentID)});
    return fetchedIncidents;
}
async function allIncidents() {
    let client = getMongoClient();
    await connect(client);

    const fetchedIncidents = await client.db("ASDdata").collection("Complaints").find().toArray();
    return fetchedIncidents;
}

//store queries
async function getAllStores() {
    let client = getMongoClient();
    await connect(client);

    const fetchedStores = await client.db("ASDdata").collection("SCentres").find().toArray();
    return fetchedStores;
}
async function addStore(store) {
    let client = getMongoClient();
    await connect(client);

    centre = store.sCentre;
    delete store.sCentre;
    const addedStore = await client.db("ASDdata").collection("SCentres").updateOne(
        { name: centre },
        { $push: { stores: store } });

    return addedStore;
}

async function addCentre(centre) {
    let client = getMongoClient();
    await connect(client);

    const stores = [];

    let centreName = centre.cName;

    const addedCentre = await client.db("ASDdata").collection("SCentres").insertOne(
        {
            name: centreName,
            stores: stores
        });

    return addedCentre;
}

async function deleteStore(store) {
    //connect to db
    let client = getMongoClient();
    await connect(client);

    //delete store.sCentre

    //query DB. delete
    const centre = await client.db("ASDdata").collection("SCentres").findOne({name: store.sCentre})

    //finding the store to remove
    const removedStore = centre.stores.find((s) => s.sName == store.sName);
    //filtering the store for update
    const newStoreArr = centre.stores.filter(store => store !== removedStore);

    console.log("returned store",newStoreArr)

    const storeArr = await client.db("ASDdata").collection("SCentres").updateOne(
        {name: store.sCentre}, { $set: { stores: newStoreArr }});
    console.log(storeArr)
    return storeArr;
}

async function deleteCentre(centre) {
    //connect to db
    let client = getMongoClient();
    await connect(client);

    //query DB. delete
    const deleted = await client.db("ASDdata").collection("SCentres").deleteOne({name: centre.cName})
    return deleted;
}

//centre employee queries (admin queries)
async function addID(newUser) {
    //connect to db
    let client = getMongoClient();
    await connect(client);

    try {
        //query DB. add user
        const user = await client.db("ASDdata").collection("StaffID").insertOne(
            {
                eid: newUser.eid,
                storeId: newUser.storeId,
                centreId: newUser.centreId,
                fName: newUser.fName,
                lName: newUser.lName
            });
        console.log("new employee id: ", newUser.eid);
    } catch (error) {
        console.log(error);
    }

}
async function findID(employeeId){
    //connect to db
    let client = getMongoClient();
    await connect(client);

    //query DB. Fetch users
    const fetchedUser = await client.db("ASDdata").collection("StaffID").findOne({eid: employeeId});

    return fetchedUser;
}
async function findAllID(){
    //connect to db
    let client = getMongoClient();
    await connect(client);

    //query DB. Fetch users
    const fetchedUser = await client.db("ASDdata").collection("StaffID").find().toArray();
    return fetchedUser;
}
async function deleteID(eid) {
    //connect to db
    let client = getMongoClient();
    await connect(client);

    console.log(eid);
    //query DB. add incident report
    const fetchedIncidents = await client.db("ASDdata").collection("StaffID").deleteOne({eid: eid});
    return fetchedIncidents;
}
async function updateID(eid, update){
    //connect to db
    let client = getMongoClient();
    await connect(client);

    //query DB. update employee
    const updateEmployee = await client.db("ASDdata").collection("StaffID").updateOne(
        { eid: eid },
        { $set: update });

    return updateEmployee;
}
async function getAllOffenders() {
  //connect to db
  let client = getMongoClient();
  await connect(client);

  //query DB. Fetch all offenders
  let offenderList = await client.db('ASDdata').collection('OffendersTEST').find().toArray();

  //disconnect and return
  await disconnect(client);
  return offenderList;
}
async function addOffender(offender) {
  //connect to db
  let client = getMongoClient();
  await connect(client);

  //query DB. add offender
  const user = await client.db("ASDdata").collection("OffendersTEST").insertOne(offender);
  console.log("new offender added: ", offender._id.toString());
  return offender._id.toString();
}




//Guest queries
async function guestReportIncident(incident){
    //connect to db
    let client = getMongoClient();
    await connect(client);

    //query DB. add incident report
    const report = await client.db("ASDdata").collection("GuestComplaints").insertOne(incident);
    console.log("new report added: ", report);
}
async function guestIncidents(account){
    //connect to db
    let client = getMongoClient();
    await connect(client);
    console.log("ACCOUNT NUMBER: ", account)
    //query DB. add incident report
    const fetchedIncidents = await client.db("ASDdata").collection("GuestComplaints").find(account).toArray();
    return fetchedIncidents;
}
async function guestIncident(account,CID){
    //connect to db
    let client = getMongoClient();
    await connect(client);
    console.log("ACCOUNT NUMBER: ", account)
    //query DB. add incident report
    const fetchedIncident = await client.db("ASDdata").collection("GuestComplaints").findOne({_id: ObjectId(CID)});
    return fetchedIncident;
}
async function guestUpdateIncident(incident, update){
    var updateIncident;

    //connect to db
    let client = getMongoClient();
    await connect(client);

    console.log(incident);
    //query DB. add incident report

    if(!incident.userId){
        updateIncident = await client.db("ASDdata").collection("GuestComplaints").updateOne(
            { _id: ObjectId(incident._id) }, { $set: update });
    }else{
        updateIncident = await client.db("ASDdata").collection("GuestComplaints").updateOne(
            { _id: ObjectId(incident._id), userId: incident.userId },
            { $set: update });
    }

    return updateIncident;
}
async function guestDeleteIncident(incidentID, userID) {
    //connect to db
    let client = getMongoClient();
    await connect(client);

    //query DB. add incident report
    const fetchedIncidents = await client.db("ASDdata").collection("GuestComplaints").deleteOne({_id: ObjectId(incidentID), userId: userID});
    return fetchedIncidents;
}
async function AdminDeleteGuestIncident(incidentID) {
    //connect to db
    let client = getMongoClient();
    await connect(client);

    //query DB. add incident report
    const fetchedIncidents = await client.db("ASDdata").collection("GuestComplaints").deleteOne({_id: ObjectId(incidentID)});
    return fetchedIncidents;
}
async function allGuestIncidents() {
    let client = getMongoClient();
    await connect(client);

    const fetchedIncidents = await client.db("ASDdata").collection("GuestComplaints").find().toArray();
    return fetchedIncidents;
}

//Guest inquiry
async function submitInquiry(inquiry){
    //connect to db
    let client = getMongoClient();
    await connect(client);

    //query DB. add incident report
    const inquiry = await client.db("ASDdata").collection("Inquiry").insertOne(inquiry);
    console.log("new inquiry added: ", inquiry);
}

module.exports = {
    getAllUsers: getAllUsers, addUser,addUserAdmin, findUser, reportIncident, userIncidents, deleteIncident, updateIncident, userIncident, addID , deleteID, updateID, findID, findAllID, deleteUser, updateUser, AdminDeleteIncident, allIncidents, getAllStores, addStore, findUserByEmail, deleteStore, getAllOffenders, addOffender, guestReportIncident, guestIncidents, guestIncident, guestUpdateIncident, guestDeleteIncident, AdminDeleteGuestIncident, submitInquiry
};

