const AWS = require('aws-sdk');
const jwt = require('jsonwebtoken');
const dynamodb = new AWS.DynamoDB.DocumentClient();

const COMPRAS_TABLE = process.env.COMPRAS_TABLE;

exports.handler = async (event) => {
    try {
        // Obtener el token del encabezado Authorization
        const token = event.headers.Authorization.split(' ')[1];

        // Verificar el token utilizando el microservicio Usuario
        const authPayload = await verifyToken(token);

        if (!authPayload) {
            return {
                statusCode: 403,
                body: JSON.stringify({ message: 'Token inválido o expirado' })
            };
        }

        const id_usuario = authPayload.user_id; // El ID del usuario autenticado
        const data = JSON.parse(event.body);

        // Eliminar la compra
        await dynamodb.delete({
            TableName: COMPRAS_TABLE,
            Key: {
                id_usuario: id_usuario,
                id_compra: data.id_compra
            }
        }).promise();

        return {
            statusCode: 200,
            body: JSON.stringify({ message: 'Compra eliminada con éxito' })
        };
    } catch (error) {
        console.error(error);
        return {
            statusCode: 500,
            body: JSON.stringify({ message: 'Ocurrió un error al eliminar la compra' })
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
