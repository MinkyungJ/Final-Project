const jwt = require('jsonwebtoken');
const AWS = require('aws-sdk');
const ddb = new AWS.DynamoDB.DocumentClient();

// DynamoDB에서 사용자 정보를 조회하는 함수
async function getUser(email, password) {
  const params = {
    TableName: 'dynamodb_user',
    Key: {
      email: email,
      password: password,
    },
  };

  const result = await ddb.get(params).promise();
  return result.Item;
}

exports.handler = async (event, context, callback) => {
  try {
    // Get the JWT token from the request headers
    const authorizationHeader = event.headers.Authorization;
    const token = authorizationHeader.replace('Bearer ', '');

    // Verify and decode the token
    const decoded = jwt.verify(token, 'yourSecretKey');

    // Get the email and password from the decoded token
    const email = decoded.email;
    const password = decoded.password;

    // DynamoDB에서 사용자 정보를 조회
    const user = await getUser(email, password);

    if (!user) {
      // User not found
      return {
        statusCode: 404,
        body: JSON.stringify({ message: 'User not found' }),
      };
    }

    if (user.password === password) {
      // Passwords match, login successful
      const response = {
        statusCode: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Credentials': true,
        },
        body: JSON.stringify({ message: 'Login successful' }),
      };

      // Allow the request using the user's email as principalId
      callback(null, generateAllow(email, event.methodArn, response));
    } else {
      // Passwords do not match, login failed
      return {
        statusCode: 401,
        body: JSON.stringify({ message: 'Login failed' }),
      };
    }
  } catch (error) {
    console.log(error);
    return {
      statusCode: 500,
      body: 'Error occurred',
    };
  }
};

function generateAllow(principalId, resource, response) {
  return {
    principalId: principalId,
    policyDocument: {
      Version: '2012-10-17',
      Statement: [
        {
          Action: 'execute-api:Invoke',
          Effect: 'Allow',
          Resource: resource,
        },
      ],
    },
    ...response,
  };
}

