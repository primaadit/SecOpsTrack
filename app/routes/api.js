/**
 * SecOpsTrack — Red vs Blue CTF Lab | by SalimLabs
 * Author  : Prima Praditya | github.com/primaadit/SecOpsTrack
 * ⚠  Intentionally vulnerable — isolated environments only
 */
const express = require('express');
const router = express.Router();

// ============================================================
// POST /api/login
// VULNERABILITY: Issues adm_sess BEFORE MFA is completed
// This is the premature session issuance flaw
// FLAGS: SALIMLABS{pre_mfa_session}, SALIMLABS{False}, SALIMLABS{adm_sess}
// ============================================================
router.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (username === 'admin' && password === 'admin123') {
    // Set pre-auth session cookie (HttpOnly: false — intentional vulnerability)
    // FLAG: SALIMLABS{pre_mfa_session}, SALIMLABS{pending_mfa_verification}, SALIMLABS{False}
    res.cookie('pre_mfa_session', 'pending_mfa_verification', {
      httpOnly: false,
      sameSite: 'lax',
      path: '/'
    });

    // INTENTIONAL FLAW: adm_sess issued BEFORE MFA is verified
    // FLAG: SALIMLABS{adm_sess}
    res.cookie('adm_sess', 'adm_sess_4dm1n_s3cr3t_t0k3n_2024', {
      httpOnly: false,
      sameSite: 'lax',
      path: '/'
    });

    return res.redirect('/mfa');
  }

  return res.redirect('/login?error=invalid');
});

module.exports = router;
