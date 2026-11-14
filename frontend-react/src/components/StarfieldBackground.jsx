import React, { useEffect, useRef } from 'react';

/**
 * ThreatPath AI — Cinematic Deep Space StarfieldBackground Component
 *
 * Visual Identity (Matched to Uploaded Reference Images):
 * - Nearly black & deep navy space (#01040a -> #040d1a -> #061527).
 * - Subtle, organic dark-cyan, teal, and deep-blue nebula clouds rendered to an offscreen canvas buffer
 *   for zero per-frame gradient overhead.
 * - ~360 naturally distributed astrophotography stars across 3 tiers (including a central open star cluster
 *   and galactic band density variation):
 *     1. Hundreds of tiny pinprick field stars (0.4px - 1.1px) in cool white, ice-blue, cyan, and faint warm gold.
 *     2. Medium luminous cyan/blue stars (1.15px - 1.85px) with soft atmospheric halos.
 *     3. 6 prominent glowing beacon stars with delicate 4-point optical diffraction spikes (horizontal + vertical tapered rays).
 * - Zero geometric lines or cartoon effects.
 *
 * Backend Lifecycle Synchronization:
 * - 'Sleeping' / 'Paused': 100% static reference starfield; halts requestAnimationFrame loop (0% CPU/GPU)
 *   except during brief (~480ms) localized button-click star ripples.
 * - 'Starting' / 'Awaiting Permission': Smooth activation ramp with a subtle blue-cyan energy wave.
 * - 'Awake / Protecting': Slow, cinematic multi-directional star drift, very subtle twinkling, and occasional
 *   natural star brightening.
 * - 'Stopping': Smooth exponential deceleration until stars freeze completely into the static starfield.
 */
export function StarfieldBackground({
  lifecycleState = 'Sleeping',
  isInvestigating = false,
  reducedMotionOverride = false,
  isLightMode = false
}) {
  const canvasRef = useRef(null);
  const stateRef = useRef({
    lifecycleState,
    isInvestigating,
    reducedMotionOverride,
    isLightMode,
    osReducedMotion: false,
    isCoarsePointer: false,
    tabHidden: false,
    width: 1280,
    height: 800,
    dpr: 1,
    currentSpeed: 0,
    targetSpeed: 0,
    frameTick: 0,
    mouseX: -9999,
    mouseY: -9999,
    parallaxX: 0,
    parallaxY: 0,
    rafId: null,
    isLoopRunning: false,
    nebulaCanvas: null,
    stars: [],
    ripples: [],
    particles: []
  });

  useEffect(() => {
    const st = stateRef.current;
    const prevLifecycle = st.lifecycleState;
    st.lifecycleState = lifecycleState;
    st.isInvestigating = isInvestigating;
    st.reducedMotionOverride = reducedMotionOverride;
    st.isLightMode = isLightMode;

    const motionBlocked = st.osReducedMotion || st.reducedMotionOverride;
    if (motionBlocked) {
      st.targetSpeed = 0;
      st.currentSpeed = 0;
    } else if (lifecycleState === 'Awake / Protecting') {
      st.targetSpeed = isInvestigating ? 1.25 : 1.0;
    } else if (lifecycleState === 'Starting' || lifecycleState === 'Awaiting Permission') {
      st.targetSpeed = 0.42;
    } else if (lifecycleState === 'Stopping') {
      st.targetSpeed = 0;
    } else {
      st.targetSpeed = 0;
    }

    if (!motionBlocked && prevLifecycle !== lifecycleState) {
      if (lifecycleState === 'Starting') {
        spawnRipple(st, st.width * 0.5, st.height * 0.46, 'rgba(34, 211, 238, ', Math.max(st.width, st.height) * 0.38, 8);
      } else if (lifecycleState === 'Awake / Protecting') {
        spawnRipple(st, st.width * 0.5, st.height * 0.46, 'rgba(56, 189, 248, ', Math.max(st.width, st.height) * 0.48, 10);
      } else if (lifecycleState === 'Stopping') {
        spawnRipple(st, st.width * 0.5, st.height * 0.46, 'rgba(56, 189, 248, ', 140, 4);
      }
    }

    if (st.rebuildNebula && prevLifecycle === st.lifecycleState) {
      st.rebuildNebula();
    }
    if (st.ensureLoop) {
      st.ensureLoop();
    }
  }, [lifecycleState, isInvestigating, reducedMotionOverride, isLightMode]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return undefined;
    const ctx = canvas.getContext('2d');
    if (!ctx) return undefined;

    const st = stateRef.current;

    // Pre-allocate Ripple Ring Pool (8 slots) and Subtle Star-Dust Pool (48 slots)
    st.ripples = Array.from({ length: 8 }, () => ({
      active: false,
      x: 0,
      y: 0,
      radius: 0,
      maxRadius: 96,
      alpha: 0,
      colorPrefix: 'rgba(56, 189, 248, '
    }));

    st.particles = Array.from({ length: 48 }, () => ({
      active: false,
      x: 0,
      y: 0,
      vx: 0,
      vy: 0,
      radius: 1.0,
      alpha: 0,
      decay: 0.026,
      colorPrefix: 'rgba(186, 230, 253, '
    }));

    // Build offscreen cached deep-space & nebula cloud layer (matches reference images 1, 2 & 3)
    const buildNebulaBuffer = (w, h) => {
      const off = document.createElement('canvas');
      off.width = w;
      off.height = h;
      const octx = off.getContext('2d');
      if (!octx) return;

      if (st.isLightMode) {
        const lg = octx.createLinearGradient(0, 0, 0, h);
        lg.addColorStop(0, '#050d1a');
        lg.addColorStop(1, '#02060d');
        octx.fillStyle = lg;
        octx.fillRect(0, 0, w, h);
      } else {
        // 1. Nearly black & deep navy astrophotography base
        const baseGrad = octx.createRadialGradient(
          w * 0.52, h * 0.48, 10,
          w * 0.5, h * 0.5, Math.max(w, h) * 0.85
        );
        baseGrad.addColorStop(0, '#051122');
        baseGrad.addColorStop(0.45, '#030914');
        baseGrad.addColorStop(0.8, '#02050c');
        baseGrad.addColorStop(1, '#010307');
        octx.fillStyle = baseGrad;
        octx.fillRect(0, 0, w, h);

        // 2. Subtle multi-layered dark-cyan, teal & deep-blue nebula clouds (matching image_97bbda.jpg)
        const nebulaClouds = [
          // Central cyan-teal emission nebula cloud
          { x: w * 0.49, y: h * 0.49, r: Math.min(w, h) * 0.34, c0: 'rgba(6, 182, 212, 0.11)', c1: 'rgba(14, 116, 144, 0.045)', c2: 'rgba(0, 0, 0, 0)' },
          // Brighter inner cyan core wisp
          { x: w * 0.52, y: h * 0.47, r: Math.min(w, h) * 0.16, c0: 'rgba(34, 211, 238, 0.09)', c1: 'rgba(20, 184, 166, 0.03)', c2: 'rgba(0, 0, 0, 0)' },
          // Right-hand electric cyan-blue nebula plume
          { x: w * 0.88, y: h * 0.36, r: Math.min(w, h) * 0.29, c0: 'rgba(14, 165, 233, 0.10)', c1: 'rgba(2, 132, 199, 0.035)', c2: 'rgba(0, 0, 0, 0)' },
          // Upper-left subtle teal-emerald dust cloud
          { x: w * 0.28, y: h * 0.28, r: Math.min(w, h) * 0.26, c0: 'rgba(20, 184, 166, 0.065)', c1: 'rgba(15, 118, 110, 0.02)', c2: 'rgba(0, 0, 0, 0)' },
          // Lower-left deep sapphire nebula haze
          { x: w * 0.18, y: h * 0.72, r: Math.min(w, h) * 0.32, c0: 'rgba(29, 78, 216, 0.075)', c1: 'rgba(30, 58, 138, 0.025)', c2: 'rgba(0, 0, 0, 0)' },
          // Lower-center-right deep blue wisp
          { x: w * 0.64, y: h * 0.68, r: Math.min(w, h) * 0.28, c0: 'rgba(3, 105, 161, 0.07)', c1: 'rgba(12, 74, 110, 0.02)', c2: 'rgba(0, 0, 0, 0)' }
        ];

        for (let i = 0; i < nebulaClouds.length; i += 1) {
          const nc = nebulaClouds[i];
          const ng = octx.createRadialGradient(nc.x, nc.y, 2, nc.x, nc.y, nc.r);
          ng.addColorStop(0, nc.c0);
          ng.addColorStop(0.5, nc.c1);
          ng.addColorStop(1, nc.c2);
          octx.fillStyle = ng;
          octx.beginPath();
          octx.arc(nc.x, nc.y, nc.r, 0, Math.PI * 2);
          octx.fill();
        }
      }
      st.nebulaCanvas = off;
    };

    st.rebuildNebula = () => buildNebulaBuffer(st.width, st.height);

    const initStars = (w, h) => {
      // Scale star count for a rich, realistic deep-space field (320 to 460 stars)
      const targetCount = Math.min(460, Math.max(260, Math.floor((w * h) / 3600)));
      const palette = [
        { rgb: '241, 245, 249', weight: 0.50 }, // Crisp stellar white
        { rgb: '186, 230, 253', weight: 0.24 }, // Ice blue
        { rgb: '56, 189, 248', weight: 0.14 },  // Deep cyan-blue
        { rgb: '34, 211, 238', weight: 0.07 },  // Bright cyan
        { rgb: '253, 230, 138', weight: 0.05 }  // Subtle warm gold/amber star pinpricks (like image_97bea4.png)
      ];

      // Deterministic pseudo-random helper so the starfield looks naturally structured
      const nextStars = [];

      // 1. Create 6 prominent diffraction-spike beacon stars matching image_97bea4.png & image_97bbda.jpg
      const beaconPositions = [
        { xr: 0.89, yr: 0.16, radius: 2.35, spikeLen: 26, rgb: '224, 242, 254' }, // Top-right bright diffraction star
        { xr: 0.17, yr: 0.54, radius: 1.95, spikeLen: 19, rgb: '186, 230, 253' }, // Mid-left diffraction star
        { xr: 0.09, yr: 0.74, radius: 2.15, spikeLen: 22, rgb: '224, 242, 254' }, // Bottom-left diffraction star
        { xr: 0.53, yr: 0.48, radius: 1.85, spikeLen: 16, rgb: '165, 243, 252' }, // Central nebula core star
        { xr: 0.78, yr: 0.37, radius: 1.80, spikeLen: 15, rgb: '56, 189, 248' },  // Right nebula bright star
        { xr: 0.82, yr: 0.81, radius: 1.75, spikeLen: 15, rgb: '186, 230, 253' }  // Lower-right bright star
      ];

      for (let i = 0; i < beaconPositions.length; i += 1) {
        const bp = beaconPositions[i];
        const angle = (i * 1.17) % (Math.PI * 2);
        nextStars.push({
          x: bp.xr * w,
          y: bp.yr * h,
          vx: Math.cos(angle) * 0.055,
          vy: Math.sin(angle) * 0.055,
          depth: 0.95,
          radius: bp.radius,
          baseAlpha: 0.92,
          twinklePhase: i * 1.3,
          twinkleSpeed: 0.012,
          rgb: bp.rgb,
          isGlow: true,
          hasDiffraction: true,
          spikeLen: bp.spikeLen,
          boostAlpha: 0,
          flareAlpha: 0
        });
      }

      // 2. Create ~48 central open-cluster stars (matching the central star cluster in image_97bea4.png)
      const clusterCount = 48;
      for (let i = 0; i < clusterCount; i += 1) {
        // Gaussian-like radial distribution around center (0.52 * w, 0.54 * h)
        const u1 = Math.max(0.0001, Math.random());
        const u2 = Math.random();
        const gaussR = Math.sqrt(-2.0 * Math.log(u1)) * 0.048 * Math.min(w, h);
        const theta = u2 * Math.PI * 2;
        const cx = w * 0.52 + Math.cos(theta) * gaussR;
        const cy = h * 0.54 + Math.sin(theta) * gaussR;
        const depth = 0.45 + Math.random() * 0.5;
        const moveAngle = Math.random() * Math.PI * 2;
        const speed = (0.03 + Math.random() * 0.07) * depth;
        const isWarm = Math.random() < 0.14;
        nextStars.push({
          x: (cx + w) % w,
          y: (cy + h) % h,
          vx: Math.cos(moveAngle) * speed,
          vy: Math.sin(moveAngle) * speed,
          depth,
          radius: 0.55 + Math.random() * 1.05,
          baseAlpha: 0.38 + Math.random() * 0.52,
          twinklePhase: Math.random() * Math.PI * 2,
          twinkleSpeed: 0.01 + Math.random() * 0.018,
          rgb: isWarm ? '253, 230, 138' : (Math.random() < 0.4 ? '186, 230, 253' : '241, 245, 249'),
          isGlow: depth > 0.82,
          hasDiffraction: false,
          spikeLen: 0,
          boostAlpha: 0,
          flareAlpha: 0
        });
      }

      // 3. Create remaining natural field stars distributed across the entire sky
      const remaining = targetCount - nextStars.length;
      for (let i = 0; i < remaining; i += 1) {
        const r = Math.random();
        let acc = 0;
        let chosenRgb = palette[0].rgb;
        for (let p = 0; p < palette.length; p += 1) {
          acc += palette[p].weight;
          if (r <= acc) {
            chosenRgb = palette[p].rgb;
            break;
          }
        }
        // Favor tiny crisp pinprick stars (power-law distribution like real astrophotography)
        const sizeRoll = Math.pow(Math.random(), 2.2);
        const depth = 0.25 + sizeRoll * 0.75;
        const radius = 0.42 + sizeRoll * 1.45;
        const angle = Math.random() * Math.PI * 2;
        // Slow, serene drift in different directions when Awake
        const baseSpeed = (0.035 + Math.random() * 0.12) * depth;

        nextStars.push({
          x: Math.random() * w,
          y: Math.random() * h,
          vx: Math.cos(angle) * baseSpeed,
          vy: Math.sin(angle) * baseSpeed,
          depth,
          radius,
          baseAlpha: 0.18 + Math.random() * 0.68,
          twinklePhase: Math.random() * Math.PI * 2,
          twinkleSpeed: 0.008 + Math.random() * 0.018,
          rgb: chosenRgb,
          isGlow: radius > 1.35,
          hasDiffraction: false,
          spikeLen: 0,
          boostAlpha: 0,
          flareAlpha: 0
        });
      }

      st.stars = nextStars;
    };

    const handleResize = () => {
      const w = window.innerWidth || 1280;
      const h = window.innerHeight || 800;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      st.width = w;
      st.height = h;
      st.dpr = dpr;
      canvas.width = Math.floor(w * dpr);
      canvas.height = Math.floor(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      buildNebulaBuffer(w, h);
      initStars(w, h);
      renderFrame(true);
    };

    const hasActiveTransientEffects = () => {
      for (let i = 0; i < st.ripples.length; i += 1) {
        if (st.ripples[i].active) return true;
      }
      for (let i = 0; i < st.particles.length; i += 1) {
        if (st.particles[i].active) return true;
      }
      for (let i = 0; i < st.stars.length; i += 1) {
        if (st.stars[i].boostAlpha > 0.01 || st.stars[i].flareAlpha > 0.01) return true;
      }
      return false;
    };

    const renderFrame = (forceStaticDraw = false) => {
      const w = st.width;
      const h = st.height;
      const motionBlocked = st.osReducedMotion || st.reducedMotionOverride;

      if (motionBlocked) {
        st.currentSpeed = 0;
      } else if (st.lifecycleState === 'Sleeping' || st.lifecycleState === 'Paused') {
        st.currentSpeed = st.currentSpeed < 0.006 ? 0 : st.currentSpeed * 0.86;
      } else if (st.lifecycleState === 'Stopping') {
        st.currentSpeed = st.currentSpeed < 0.005 ? 0 : st.currentSpeed * 0.90;
      } else {
        st.currentSpeed += (st.targetSpeed - st.currentSpeed) * 0.05;
      }

      const speed = st.currentSpeed;
      const isMoving = speed > 0.002 && !motionBlocked;
      if (isMoving) {
        st.frameTick += 1;
        // Occasionally brighten a random star gently in Active mode
        if (st.frameTick % 45 === 0 && st.stars.length > 0) {
          const pick = st.stars[Math.floor(Math.random() * st.stars.length)];
          pick.flareAlpha = 0.38;
        }
      }

      // 1. Draw cached deep-space & nebula cloud layer
      if (st.nebulaCanvas) {
        ctx.drawImage(st.nebulaCanvas, 0, 0, w, h);
      } else {
        ctx.fillStyle = '#02050c';
        ctx.fillRect(0, 0, w, h);
      }

      // Very gentle depth parallax on desktop cursor movement when Awake
      if (isMoving && !st.isCoarsePointer && st.mouseX > 0) {
        const targetPx = ((st.mouseX / w) - 0.5) * 10;
        const targetPy = ((st.mouseY / h) - 0.5) * 10;
        st.parallaxX += (targetPx - st.parallaxX) * 0.04;
        st.parallaxY += (targetPy - st.parallaxY) * 0.04;
      } else if (!isMoving) {
        st.parallaxX *= 0.88;
        st.parallaxY *= 0.88;
      }

      // 2. Update & draw stars
      const stars = st.stars;
      for (let i = 0; i < stars.length; i += 1) {
        const s = stars[i];
        if (isMoving) {
          s.x += s.vx * speed;
          s.y += s.vy * speed;
          if (s.x < -8) s.x = w + 8;
          else if (s.x > w + 8) s.x = -8;
          if (s.y < -8) s.y = h + 8;
          else if (s.y > h + 8) s.y = -8;
          s.twinklePhase += s.twinkleSpeed * speed;
        }

        if (s.boostAlpha > 0.004) s.boostAlpha *= 0.90;
        else s.boostAlpha = 0;

        if (s.flareAlpha > 0.004) s.flareAlpha *= 0.96;
        else s.flareAlpha = 0;

        const drawX = s.x + st.parallaxX * s.depth;
        const drawY = s.y + st.parallaxY * s.depth;

        // Subtle twinkling only when Awake; completely steady when Sleeping
        const twinkleOffset = isMoving ? Math.sin(s.twinklePhase) * 0.11 : 0;
        const alpha = Math.min(1.0, Math.max(0.10, s.baseAlpha + twinkleOffset + s.boostAlpha + s.flareAlpha));

        // Soft radial halo for glowing stars or ripple-boosted stars
        if (s.isGlow || s.boostAlpha > 0.08 || s.flareAlpha > 0.08) {
          const glowRadius = s.hasDiffraction
            ? s.radius * 6.5
            : s.radius * (s.boostAlpha > 0.08 ? 4.0 : 3.2);
          const halo = ctx.createRadialGradient(drawX, drawY, 0, drawX, drawY, glowRadius);
          halo.addColorStop(0, `rgba(${s.rgb}, ${Math.min(0.65, alpha * 0.48)})`);
          halo.addColorStop(0.45, `rgba(56, 189, 248, ${alpha * 0.14})`);
          halo.addColorStop(1, 'rgba(0, 0, 0, 0)');
          ctx.fillStyle = halo;
          ctx.beginPath();
          ctx.arc(drawX, drawY, glowRadius, 0, Math.PI * 2);
          ctx.fill();
        }

        // Core star pinpoint
        ctx.fillStyle = `rgba(${s.rgb}, ${alpha})`;
        ctx.beginPath();
        ctx.arc(drawX, drawY, s.radius + s.boostAlpha * 0.55, 0, Math.PI * 2);
        ctx.fill();

        // 4-point optical diffraction spikes on prominent beacon stars (matching image_97bea4.png)
        if (s.hasDiffraction) {
          const len = s.spikeLen * (1 + s.boostAlpha * 0.35 + (isMoving ? Math.sin(s.twinklePhase) * 0.06 : 0));
          const spikeAlpha = Math.min(0.85, alpha * 0.68);

          // Horizontal tapered diffraction spike
          const hGrad = ctx.createLinearGradient(drawX - len, drawY, drawX + len, drawY);
          hGrad.addColorStop(0, 'rgba(186, 230, 253, 0)');
          hGrad.addColorStop(0.5, `rgba(241, 245, 249, ${spikeAlpha})`);
          hGrad.addColorStop(1, 'rgba(186, 230, 253, 0)');
          ctx.strokeStyle = hGrad;
          ctx.lineWidth = 1.05;
          ctx.beginPath();
          ctx.moveTo(drawX - len, drawY);
          ctx.lineTo(drawX + len, drawY);
          ctx.stroke();

          // Vertical tapered diffraction spike
          const vGrad = ctx.createLinearGradient(drawX, drawY - len, drawX, drawY + len);
          vGrad.addColorStop(0, 'rgba(186, 230, 253, 0)');
          vGrad.addColorStop(0.5, `rgba(241, 245, 249, ${spikeAlpha})`);
          vGrad.addColorStop(1, 'rgba(186, 230, 253, 0)');
          ctx.strokeStyle = vGrad;
          ctx.lineWidth = 1.05;
          ctx.beginPath();
          ctx.moveTo(drawX, drawY - len);
          ctx.lineTo(drawX, drawY + len);
          ctx.stroke();
        }
      }

      // 3. Draw subtle localized button-click ripples & tiny star-dust motes
      if (!motionBlocked) {
        for (let i = 0; i < st.ripples.length; i += 1) {
          const rp = st.ripples[i];
          if (!rp.active) continue;
          rp.radius += (rp.maxRadius - rp.radius) * 0.10 + 1.1;
          rp.alpha *= 0.90;
          if (rp.alpha < 0.01 || rp.radius >= rp.maxRadius) {
            rp.active = false;
            continue;
          }
          ctx.strokeStyle = `${rp.colorPrefix}${rp.alpha})`;
          ctx.lineWidth = 1.1;
          ctx.beginPath();
          ctx.arc(rp.x, rp.y, rp.radius, 0, Math.PI * 2);
          ctx.stroke();
        }

        for (let i = 0; i < st.particles.length; i += 1) {
          const pt = st.particles[i];
          if (!pt.active) continue;
          pt.x += pt.vx;
          pt.y += pt.vy;
          pt.vx *= 0.94;
          pt.vy *= 0.94;
          pt.alpha -= pt.decay;
          if (pt.alpha <= 0.01) {
            pt.active = false;
            continue;
          }
          ctx.fillStyle = `${pt.colorPrefix}${pt.alpha})`;
          ctx.beginPath();
          ctx.arc(pt.x, pt.y, pt.radius, 0, Math.PI * 2);
          ctx.fill();
        }
      }

      const shouldContinue =
        !st.tabHidden &&
        !motionBlocked &&
        (isMoving || hasActiveTransientEffects());

      if (shouldContinue && !forceStaticDraw) {
        st.rafId = window.requestAnimationFrame(() => renderFrame(false));
      } else {
        st.isLoopRunning = false;
        st.rafId = null;
      }
    };

    const ensureLoop = () => {
      if (st.tabHidden) return;
      const motionBlocked = st.osReducedMotion || st.reducedMotionOverride;
      if (motionBlocked) {
        if (st.rafId) {
          window.cancelAnimationFrame(st.rafId);
          st.rafId = null;
        }
        st.isLoopRunning = false;
        renderFrame(true);
        return;
      }
      const needsAnim =
        st.targetSpeed > 0 ||
        st.currentSpeed > 0.002 ||
        hasActiveTransientEffects();
      if (needsAnim && !st.isLoopRunning) {
        st.isLoopRunning = true;
        st.rafId = window.requestAnimationFrame(() => renderFrame(false));
      } else if (!needsAnim) {
        renderFrame(true);
      }
    };

    st.ensureLoop = ensureLoop;

    const handleGlobalClick = (e) => {
      if (st.osReducedMotion || st.reducedMotionOverride) return;
      const targetBtn = e.target && e.target.closest
        ? e.target.closest('button, .btn, .nav-item, [role="button"]')
        : null;
      if (!targetBtn || targetBtn.disabled) return;

      let clickX = e.clientX;
      let clickY = e.clientY;
      if (!clickX && !clickY && targetBtn.getBoundingClientRect) {
        const rect = targetBtn.getBoundingClientRect();
        clickX = rect.left + rect.width * 0.5;
        clickY = rect.top + rect.height * 0.5;
      }

      spawnRipple(st, clickX, clickY, 'rgba(56, 189, 248, ', 78, 6);
      ensureLoop();
    };

    const handleMouseMove = (e) => {
      if (st.isCoarsePointer || st.osReducedMotion || st.reducedMotionOverride) return;
      st.mouseX = e.clientX;
      st.mouseY = e.clientY;
    };

    const handleVisibilityChange = () => {
      st.tabHidden = document.hidden;
      if (st.tabHidden && st.rafId) {
        window.cancelAnimationFrame(st.rafId);
        st.rafId = null;
        st.isLoopRunning = false;
      } else if (!st.tabHidden) {
        ensureLoop();
      }
    };

    const motionMq = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : null;
    const pointerMq = window.matchMedia ? window.matchMedia('(pointer: coarse)') : null;
    if (motionMq) st.osReducedMotion = motionMq.matches;
    if (pointerMq) st.isCoarsePointer = pointerMq.matches;

    const handleMotionPrefChange = (ev) => {
      st.osReducedMotion = ev.matches;
      ensureLoop();
    };

    handleResize();
    ensureLoop();

    window.addEventListener('resize', handleResize, { passive: true });
    window.addEventListener('mousemove', handleMouseMove, { passive: true });
    document.addEventListener('click', handleGlobalClick, { passive: true });
    document.addEventListener('visibilitychange', handleVisibilityChange);
    if (motionMq && motionMq.addEventListener) {
      motionMq.addEventListener('change', handleMotionPrefChange);
    }

    return () => {
      if (st.rafId) window.cancelAnimationFrame(st.rafId);
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('click', handleGlobalClick);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      if (motionMq && motionMq.removeEventListener) {
        motionMq.removeEventListener('change', handleMotionPrefChange);
      }
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      style={{
        position: 'fixed',
        inset: 0,
        width: '100vw',
        height: '100vh',
        pointerEvents: 'none',
        zIndex: 0,
        display: 'block'
      }}
    />
  );
}

function spawnRipple(st, x, y, colorPrefix, maxRadius, particleCount) {
  for (let i = 0; i < st.ripples.length; i += 1) {
    const rp = st.ripples[i];
    if (!rp.active) {
      rp.active = true;
      rp.x = x;
      rp.y = y;
      rp.radius = 3;
      rp.maxRadius = maxRadius;
      rp.alpha = 0.34;
      rp.colorPrefix = colorPrefix;
      break;
    }
  }

  const radiusSq = 125 * 125;
  for (let i = 0; i < st.stars.length; i += 1) {
    const s = st.stars[i];
    const dx = s.x - x;
    const dy = s.y - y;
    const d2 = dx * dx + dy * dy;
    if (d2 < radiusSq) {
      const factor = 1 - Math.sqrt(d2) / 125;
      s.boostAlpha = Math.min(0.55, s.boostAlpha + factor * 0.45);
    }
  }

  let spawned = 0;
  for (let i = 0; i < st.particles.length && spawned < particleCount; i += 1) {
    const pt = st.particles[i];
    if (!pt.active) {
      const angle = (Math.PI * 2 * spawned) / particleCount + (Math.random() - 0.5) * 0.4;
      const speed = 0.75 + Math.random() * 1.35;
      pt.active = true;
      pt.x = x;
      pt.y = y;
      pt.vx = Math.cos(angle) * speed;
      pt.vy = Math.sin(angle) * speed;
      pt.radius = 0.8 + Math.random() * 0.9;
      pt.alpha = 0.48;
      pt.decay = 0.024 + Math.random() * 0.01;
      pt.colorPrefix = colorPrefix;
      spawned += 1;
    }
  }
}

export default StarfieldBackground;
