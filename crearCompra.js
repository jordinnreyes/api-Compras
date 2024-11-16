const AWS = require('aws-sdk');
const jwt = require('jsonwebtoken'); // Usamos la librería JWT
const uuid = require('uuid'); // Para generar IDs únicos
const dynamodb = new AWS.DynamoDB.DocumentClient();
const { DateTime } = require('luxon');

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

        // Crear el registro de la compra
        const item = {
            id_usuario: id_usuario,
            id_compra: uuid.v4(),
            id_vuelo: data.id_vuelo,
            fecha_compra: DateTime.now().toISO(),
            cantidad_boletos: data.cantidad_boletos,
            precio_total: data.precio_total,
            estado: 'pendiente' // Estado inicial
        };

        // Guardar la compra en DynamoDB
        await dynamodb.put({
            TableName: COMPRAS_TABLE,
            Item: item
        }).promise();

        return {
            statusCode: 201,
            body: JSON.stringify({ message: 'Compra creada con éxito', compra: item })
        };
    } catch (error) {
        console.error(error);
        return {
            statusCode: 500,
            body: JSON.stringify({ message: 'Ocurrió un error al crear la compra' })
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
