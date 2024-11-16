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
        const { id_compra } = event.pathParameters; // Obtener el ID de la compra desde los parámetros de la ruta

        // Consultar DynamoDB para obtener la compra específica
        const result = await dynamodb.get({
            TableName: COMPRAS_TABLE,
            Key: {
                id_usuario: id_usuario,
                id_compra: id_compra
            }
        }).promise();

        if (!result.Item) {
            return {
                statusCode: 404,
                body: JSON.stringify({ message: 'Compra no encontrada' })
            };
        }

        return {
            statusCode: 200,
            body: JSON.stringify({ compra: result.Item })
        };
    } catch (error) {
        console.error(error);
        return {
            statusCode: 500,
            body: JSON.stringify({ message: 'Ocurrió un error al obtener la compra' })
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
