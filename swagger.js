// swagger.js
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
  // apis: ['./routes/*.js'], // Points to your annotated routes
   apis: ['./routes/authRoutes.js']
};

const specs = swaggerJsdoc(options);

module.exports = (app) => {
  app.use(
    '/api-docs',
    swaggerUi.serve,
    swaggerUi.setup(specs, {
      swaggerOptions: {
        requestInterceptor: (req) => {
          // Detect the Google login initiation endpoint
          if (req.url.endsWith('/auth/client/google')) {
            // Open the Google login in a new browser tab
            window.open(req.url, '_blank');
            // Prevent Swagger from actually making the AJAX request
            return {};
          }
          return req;
        }
      }
    })
  );
};
