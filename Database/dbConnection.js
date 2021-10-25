const { MongoClient } = require('mongodb');

function getMongoClient() {
    const uri = "mongodb+srv://asdAdmin:group3@asddata.3697e.mongodb.net/ASDdata?retryWrites=true&w=majority";

    const client = new MongoClient(uri, { useUnifiedTopology: true } );
    return client;

}

async function connect(client) {
    try {
        await client.connect();
    }
    catch (e) {
        console.error(e);
    }
}

async function disconnect(client) {
    try {
        await client.close();
    }
    catch (e) {
        console.error(e);
    }
}


module.exports = {
    getMongoClient: getMongoClient,
    connect: connect,
    disconnect: disconnect,
};

