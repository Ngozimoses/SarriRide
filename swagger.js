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
          // Auto open Google login in a new tab for this specific endpoint
          if (req.url.endsWith('/auth/client/google')) {
            window.open(req.url, '_blank');
            return {}; // Prevent Swagger from actually trying to fetch JSON
          }
          return req;
        }
      }
    })
  );
};
