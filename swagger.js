const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Sarri Backend API',
      version: '1.0.0',
      description: 'API documentation for SarriRide backend services.',
    },
    servers: [
      {
        url: 'https://sarriride.onrender.com',
        description: 'Production server',
      },
    ],
  },
  apis: ['./routes/*.js'], // Points to your annotated routes
};

const specs = swaggerJsdoc(options);

module.exports = (app) => {
  app.use(
    '/api-docs',
    swaggerUi.serve,
    swaggerUi.setup(specs, {
      swaggerOptions: {
        requestInterceptor: (req) => {
          return req;
        }
      }
    })
  );
};
