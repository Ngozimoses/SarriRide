export const ForgotPassword =  async (req, res) => {
    try {
      const email = req.body.email.trim().toLowerCase();
      const user = await User.findOne({ email });
      
      if (!user) {
        return res.json({ 
          message: 'If an account exists, a reset link has been sent.' 
        });
      }

      // Generate new token
      const resetToken = crypto.randomBytes(64).toString('hex');
      const salt = crypto.randomBytes(16);
      const resetTokenId = uuidv4();

      user.resetToken = crypto.pbkdf2Sync(resetToken, salt, 100000, 64, 'sha512').toString('hex');
      user.resetTokenSalt = salt.toString('hex');
      user.resetTokenExpires = Date.now() + 15 * 60 * 1000; // 15 minutes
      user.resetTokenId = resetTokenId;
      
      await user.save();

      const resetLink = `${process.env.BACKEND_URL}/auth1/c/${resetTokenId}`;
      
      await sendEmail(
        email,
        'Password Reset',
        `Click to reset: ${resetLink}\nToken: ${resetToken}\nExpires in 15 minutes.`
      );

      res.json({ message: 'Reset link sent', status: 'success' });
    } catch (error) {
      console.error('Error:', error);
      res.status(500).json({ status: 'error', message: 'Server error' });
    }
  }

  export const UpdatePassword = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { tokenId, token, password } = req.body;

    try {
      // Find the user by the resetTokenId (UUID) and check expiration
      const user = await User.findOne({
        resetTokenId: tokenId,
        resetTokenExpires: { $gt: Date.now() }
      });

      if (!user) {
        return res.status(400).json({ 
          message: 'Invalid or expired password reset link',
          status: 'error'
        });
      }

      // Verify the provided token against the stored hash
      const saltBuffer = Buffer.from(user.resetTokenSalt, 'hex');
      const hashedToken = crypto.pbkdf2Sync(
        token,
        saltBuffer,
        100000,
        64,
        'sha512'
      ).toString('hex');

      if (hashedToken !== user.resetToken) {
        return res.status(400).json({ 
          message: 'Invalid security token',
          status: 'error'
        });
      }

      // Hash the new password
      const hashedPassword = await bcrypt.hash(password, 12);

      // Update user and clear reset fields
      user.password = hashedPassword;
      user.resetToken = undefined;
      user.resetTokenSalt = undefined;
      user.resetTokenExpires = undefined;
      user.resetTokenId = undefined;
      user.isModified = function (field) {
                return field !== 'password';
            };
      await user.save();
    

      res.status(200).json({ 
        message: 'Password updated successfully', 
        status: 'success'
      });
    } catch (error) {
      console.error('Password reset error:', error);
      res.status(500).json({ 
        message: 'An error occurred while resetting your password',
        status: 'error'
      });
    }
  }

  export const VerifyOtp = async (req, res) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
  
      const { email, otp } = req.body;
  
      try {
        // Find the user by email
        const user = await User.findOne({ email });
        if (!user) {
          console.log('User not found for email:', email);
          return res.status(400).json({ message: 'User not found' });
        }
  
        // Validate OTP
        if (user.resetToken !== otp) {
          return res.status(400).json({ message: 'Invalid OTP' });
        }
  
        if (user.resetTokenExpires < Date.now()) {
          return res.status(400).json({ message: 'OTP has expired' });
        }
  
        // Update user data
        user.isVerified = true;
        user.resetToken = undefined;
        user.resetTokenExpires = undefined;
  
        try {
          await user.save();
        } catch (dbError) {
          console.error('Error saving user data:', dbError);
          return res.status(500).json({ message: 'Failed to update user data', error: dbError.message });
        }
  
        // Return success response
        res.status(200).json({
          status: 'success',
          message: 'Verification successful',
          data: {
            user: {
              _id: user._id,
              email: user.email,
              role: user.role,
              isVerified: user.isVerified,
            },
          },
        });
      } catch (error) {
        console.error('Error verifying OTP:', error);
        res.status(500).json({ message: 'Server error' });
      }
    }

    /// forgotPassword LinkConnector
export const ForgotPasswordLinkConnector = async (req, res) => {
  try {
    console.log('Received token ID:', req.params.id);
    console.log('Current time:', new Date());
    
    const user = await User.findOne({
      resetTokenId: req.params.id,
      resetTokenExpires: { $gt: Date.now() }
    });

    console.log('Found user:', user ? user.email : 'none');
    console.log('Token expires:', user ? new Date(user.resetTokenExpires) : 'none');

    if (!user) { 
      return res.status(400).json({ 
        message: 'Invalid or expired password reset link' 
      });
    }

    const redirectUrl = `${process.env.FRONTEND_URL}/update-password?tokenId=${req.params.id}`;
    console.log('Redirecting to:', redirectUrl);
    res.redirect(redirectUrl);
    
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(500).json({ 
      message: 'An error occurred while verifying your link' 
    });
  }
}

  