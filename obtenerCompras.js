const AWS = require('aws-sdk');
const jwt = require('jsonwebtoken');
const dynamodb = new AWS.DynamoDB.DocumentClient();

const COMPRAS_TABLE = process.env.COMPRAS_TABLE;

exports.handler = async (event) => {
    try {
        // Obtener el token del encabezado Authorization
        const token = event.headers.Authorization.split(' ')[1];

        // Verificar el token
        const authPayload = await verifyToken(token);

        if (!authPayload) {
            return {
                statusCode: 403,
                body: JSON.stringify({ message: 'Token inválido o expirado' })
            };
        }

        const id_usuario = authPayload.user_id; // ID del usuario autenticado

        // Consultar DynamoDB para obtener las compras del usuario
        const result = await dynamodb.query({
            TableName: COMPRAS_TABLE,
            KeyConditionExpression: 'id_usuario = :id_usuario',
            ExpressionAttributeValues: {
                ':id_usuario': id_usuario
            }
        }).promise();

        return {
            statusCode: 200,
            body: JSON.stringify({ compras: result.Items })
        };
    } catch (error) {
        console.error(error);
        return {
            statusCode: 500,
            body: JSON.stringify({ message: 'Ocurrió un error al obtener las compras' })
        };
    }
};

async function verifyToken(token) {
    try {
        const secret = process.env.JWT_SECRET;
        const payload = jwt.verify(token, secret);
        return payload;
    } catch (error) {
        console.error('Token inválido o expirado', error);
        return null;
    }
}
