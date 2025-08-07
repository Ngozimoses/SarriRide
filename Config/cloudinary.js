const { v2: cloudinary } = require('cloudinary');
const { v4: uuidv4 } = require('uuid');
const { config } = require('dotenv');
const winston = require('winston');

config(); // Load environment variables

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.Cloud_Name,
  api_key: process.env.API_Key,
  api_secret: process.env.API_Secret,
  secure: true,
});

// Logger setup for consistency with your backend
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

// Upload function for profile and license images
const uploadToCloudinary = async (fileBuffer, type, identifier) => {
  try {
    // Validate file buffer
    if (!fileBuffer || !Buffer.isBuffer(fileBuffer)) {
      logger.warn('Invalid file buffer provided for upload', { type, identifier });
      throw new Error('Invalid file buffer');
    }

    // Validate file size (max 5MB)
    const maxSize = 5 * 1024 * 1024; // 5MB in bytes
    if (fileBuffer.length > maxSize) {
      logger.warn('File size exceeds limit', { type, identifier, size: fileBuffer.length });
      throw new Error('File size exceeds 5MB limit');
    }

    // Validate type
    const validTypes = ['profile', 'license_front', 'license_back'];
    if (!validTypes.includes(type)) {
      logger.warn('Invalid upload type', { type, identifier });
      throw new Error('Invalid upload type');
    }

    // Determine folder and public_id prefix
    const folder = type === 'profile' ? 'Sari_ride_Driver' : 'Sari_ride_Driver_Licenses';
    const prefix = {
      profile: 'profile_p',
      license_front: 'license_f',
      license_back: 'license_b'
    }[type];
    const publicId = `${prefix}_${identifier}_${uuidv4()}`; // e.g., profile_p_driver@example.com_123e4567

    // Upload to Cloudinary
    const result = await cloudinary.uploader.upload(
      `data:image/jpeg;base64,${fileBuffer.toString('base64')}`,
      {
        folder,
        public_id: publicId,
        resource_type: 'image',
        use_filename: false,
        unique_filename: true,
        allowed_formats: ['jpg', 'jpeg', 'png'],
        transformation: type === 'profile' ? [
          { width: 250, height: 250, gravity: 'faces', crop: 'thumb' },
          { radius: 'max' },
          { effect: 'outline:10', color: 'black' },
          { background: 'white' }
        ] : [
          { width: 800, height: 600, crop: 'fit' } // License images need higher resolution
        ]
      }
    );

    logger.info('File uploaded to Cloudinary', { type, identifier, url: result.secure_url, publicId });
    return result.secure_url;
  } catch (error) {
    logger.error('Cloudinary upload error', { type, identifier, error: error.message });
    throw new Error(`File upload failed: ${error.message}`);
  }
};

// Get transformed image tag (for profile images)
const getTransformedImageTag = (publicId) => {
  try {
    const tag = cloudinary.image(publicId, {
      transformation: [
        { width: 250, height: 250, gravity: 'faces', crop: 'thumb' },
        { radius: 'max' },
        { effect: 'outline:10', color: 'black' },
        { background: 'white' }
      ]
    });
    logger.info('Transformed image tag generated', { publicId });
    return tag;
  } catch (error) {
    logger.error('Error generating transformed image tag', { publicId, error: error.message });
    throw new Error('Failed to generate image tag');
  }
};

// Get asset info (optional, for color analysis)
const getAssetInfo = async (publicId) => {
  try {
    const result = await cloudinary.api.resource(publicId, {
      colors: true
    });
    logger.info('Asset info retrieved', { publicId });
    return result.colors;
  } catch (error) {
    logger.error('Error fetching asset info', { publicId, error: error.message });
    return null;
  }
};

module.exports = {
  cloudinary,
  uploadToCloudinary,
  getTransformedImageTag,
  getAssetInfo
};





// // THIS FILE IS FOR UPLOADING DRIVERS PICTURE
// const { v2: cloudinary } = require('cloudinary');
// const { v4 } = require('uuid');
// const { config } = require('dotenv'); 
// config(); // Load environment variables

// cloudinary.config({
//   cloud_name: process.env.Cloud_Name,
//   api_key: process.env.API_Key ,
//   api_secret: process.env.API_Secret,
//   secure: true,
// });

// const uploadToCloudinary = async (fileBuffer) => {
//   try {
   
//     const result = await cloudinary.uploader.upload(
//       `data:image/jpeg;base64,${fileBuffer.toString('base64')}`,
//       {
//         folder: 'Sari_ride_Driver',
//         public_id: `Sari_Driver_${v4()}`,   // Unique ID
//         resource_type: 'auto',        // Supports images & PDFs
//         use_filename: false,
//         unique_filename: true,
//       }
//     );

//     return result.secure_url; // Return the URL to store in DB
//   } catch (error) {
//     console.error('Cloudinary upload error:', error);
//     throw new Error('File upload failed');
//   }
// };

// const getTransformedImageTag = (publicId) => {
//   return cloudinary.image(publicId, {
//     transformation: [
//       { width: 250, height: 250, gravity: 'faces', crop: 'thumb' },
//       { radius: 'max' },
//       { effect: 'outline:10', color: 'black' },
//       { background: 'white' },
//     ],
//   });
// };

// const getAssetInfo = async (publicId) => {
//   try {
//     const result = await cloudinary.api.resource(publicId, {
//       colors: true,
//     });
//     return result.colors;
//   } catch (error) {
//     console.error('Error fetching asset info:', error);
//     return null;
//   }
// };

// module.exports = {
//   cloudinary,
//   uploadToCloudinary,
//   getTransformedImageTag,
//   getAssetInfo,
// };



