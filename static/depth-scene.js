/* Decorative Three.js scenes for the landing and workspace surfaces.
   The library is bundled locally; scenes are created only when visible. */
const sceneCanvases = [...document.querySelectorAll('[data-three-scene]')];
const motionPreference = window.matchMedia('(prefers-reduced-motion: reduce)');
let THREE;
let threeImport;

async function loadThree() {
  if (!threeImport) threeImport = import('./vendor/three.module.js');
  return threeImport;
}

function installCursorSpotlight() {
  if (!window.matchMedia('(hover: hover) and (pointer: fine)').matches) return;
  const surfaces = document.querySelectorAll('.pg-hero, .pg-capabilities, .pg-cap-card');
  surfaces.forEach((surface) => {
    surface.addEventListener('pointermove', (event) => {
      if (event.pointerType === 'touch') return;
      const bounds = surface.getBoundingClientRect();
      surface.style.setProperty('--spot-x', `${event.clientX - bounds.left}px`);
      surface.style.setProperty('--spot-y', `${event.clientY - bounds.top}px`);
      surface.dataset.spotlightActive = 'true';
    }, { passive: true });
    surface.addEventListener('pointerleave', () => {
      delete surface.dataset.spotlightActive;
    });
  });
}

installCursorSpotlight();

function createScene(canvas, THREE) {
  if (canvas.dataset.threeReady === 'true' || canvas.clientWidth < 2 || canvas.clientHeight < 2) return;
  canvas.dataset.threeReady = 'true';

  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({
      canvas,
      alpha: true,
      antialias: true,
      powerPreference: 'low-power',
      preserveDrawingBuffer: false,
    });
  } catch {
    canvas.dataset.threeUnavailable = 'true';
    return;
  }

  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.4));
  renderer.setClearColor(0x000000, 0);
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.12;

  const isLanding = canvas.dataset.threeScene === 'landing';
  const isRibbon = isLanding || canvas.dataset.threeScene === 'ribbon';
  const camera = new THREE.PerspectiveCamera(36, 1, 0.1, 40);
  camera.position.set(0, 0, isLanding ? 9.1 : (isRibbon ? 8.4 : 7.4));

  const scene = new THREE.Scene();
  const sculpture = new THREE.Group();
  scene.add(sculpture);
  sculpture.position.set(isLanding ? 0 : 0.12, isLanding ? -1.28 : -0.08, 0);
  sculpture.scale.setScalar(isLanding ? 1 : (isRibbon ? 0.82 : 0.88));

  scene.add(new THREE.AmbientLight(isLanding ? 0xeadcf5 : 0xe1d7f2, isLanding ? 1.35 : 1.15));
  const keyLight = new THREE.DirectionalLight(isLanding ? 0xffd9f3 : 0xe9d7ff, isLanding ? 3.8 : 3.1);
  keyLight.position.set(-2.5, 3.2, 5);
  scene.add(keyLight);
  const rimLight = new THREE.PointLight(isLanding ? 0xff59c8 : 0x6689d1, 20, 12, 2);
  rimLight.position.set(2.1, -1.2, 2.2);
  scene.add(rimLight);

  let core = null;
  let rings = [];
  let nodes = null;
  let ribbon = null;
  let pixels = null;
  let updateRibbon = () => {};

  if (isRibbon) {
    // Repeating beveled plates form a flexible ribbon, echoing the reference art.
    const count = isLanding ? 68 : 54;
    const plateGeometry = new THREE.BoxGeometry(0.27, 1, 0.24);
    const plateMaterial = new THREE.MeshStandardMaterial({
      color: 0xffffff,
      vertexColors: true,
      metalness: 0.3,
      roughness: 0.34,
      emissive: 0x35102d,
      emissiveIntensity: 0.32,
      flatShading: true,
    });
    ribbon = new THREE.InstancedMesh(plateGeometry, plateMaterial, count);
    ribbon.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    const matrix = new THREE.Object3D();
    const step = isLanding ? 0.285 : 0.19;
    const baseHeight = isLanding ? 2.92 : 1.62;
    const segments = Array.from({ length: count }, (_, index) => ({
      x: (index - (count - 1) / 2) * step,
      height: baseHeight + (isLanding ? 0.18 : 0.09) * Math.sin(((index - (count - 1) / 2) * step) * 0.47 + 0.8),
    }));
    updateRibbon = (seconds = 0) => {
      const peakCenter = 0.35 + 0.72 * Math.sin(seconds * 0.34);
      for (let index = 0; index < segments.length; index += 1) {
        const { x, height } = segments[index];
        const peak = (isLanding ? 1.28 : 0.66) * Math.exp(-((x - peakCenter) ** 2) / (isLanding ? 6.5 : 3.6));
        const waveA = (isLanding ? 0.34 : 0.22) * Math.sin(x * 0.62 - seconds * 0.68);
        const waveB = (isLanding ? 0.29 : 0.17) * Math.sin(x * 1.12 - seconds * 1.28);
        const waveC = (isLanding ? 0.19 : 0.1) * Math.sin(x * 1.78 - seconds * 1.92);
        const y = (isLanding ? -1.95 : -0.18) + peak + waveA + waveB + waveC;
        const slope = (isLanding ? 0.34 : 0.22) * 0.62 * Math.cos(x * 0.62 - seconds * 0.68)
          + (isLanding ? 0.29 : 0.17) * 1.12 * Math.cos(x * 1.12 - seconds * 1.28)
          + (isLanding ? 0.19 : 0.1) * 1.78 * Math.cos(x * 1.78 - seconds * 1.92)
          - (2 * (x - peakCenter) / (isLanding ? 6.5 : 3.6)) * peak;
        const depth = (isLanding ? 0.34 : 0.22) * Math.sin(x * 0.72 - seconds * 0.58) + 0.15 * Math.cos(x * 1.31 - seconds * 0.38);
        matrix.position.set(x, y, depth);
        matrix.rotation.set(
          0.1 * Math.sin(x * 0.9 - seconds * 0.82),
          0.24 * Math.sin(x * 0.57 - seconds * 0.64),
          -slope * 0.22,
        );
        matrix.scale.set(1, height + (isLanding ? 0.13 : 0.07) * Math.sin(x * 0.82 - seconds * 1.16), 1);
        matrix.updateMatrix();
        ribbon.setMatrixAt(index, matrix.matrix);
      }
      ribbon.instanceMatrix.needsUpdate = true;
    };
    // Preserve the screenshot's mixed hues while giving every tile the same base luminance.
    const palette = ['#754c82', '#a75495', '#d879b3', '#c66d91', '#c9827f', '#879dc4', '#6283b1', '#a875ba'];
    const colors = palette.map((hex) => {
      const color = new THREE.Color(hex);
      const luminance = 0.2126 * color.r + 0.7152 * color.g + 0.0722 * color.b;
      color.multiplyScalar(0.28 / luminance);
      return color;
    });
    for (let index = 0; index < count; index += 1) {
      ribbon.setColorAt(index, colors[(index + Math.floor(index / 5)) % colors.length]);
    }
    updateRibbon(0);
    if (ribbon.instanceColor) ribbon.instanceColor.needsUpdate = true;
    sculpture.add(ribbon);

    if (isLanding) {
      const pixelGroup = new THREE.Group();
      const pixelGeometry = new THREE.BoxGeometry(0.055, 0.055, 0.055);
      const pixelMaterial = new THREE.MeshBasicMaterial({ color: 0xd4c8b7, transparent: true, opacity: 0.24 });
      for (let index = 0; index < 30; index += 1) {
        const pixel = new THREE.Mesh(pixelGeometry, pixelMaterial);
        const seed = index + 1;
        pixel.position.set(
          Math.sin(seed * 12.9898) * 8.6,
          -2.7 + ((seed * 1.618) % 4.8),
          -1.4 - ((seed * 0.73) % 1.7),
        );
        pixel.scale.setScalar(0.65 + ((seed * 0.37) % 1.2));
        pixelGroup.add(pixel);
      }
      pixels = pixelGroup;
      scene.add(pixels);
    }
  } else {
    const coreGeometry = new THREE.IcosahedronGeometry(0.43, 2);
    const coreMaterial = new THREE.MeshStandardMaterial({
      color: 0xb85bb0,
      metalness: 0.52,
      roughness: 0.23,
      emissive: 0x55266d,
      emissiveIntensity: 0.62,
      flatShading: true,
    });
    core = new THREE.Mesh(coreGeometry, coreMaterial);
    sculpture.add(core);

    const wire = new THREE.LineSegments(
      new THREE.EdgesGeometry(coreGeometry, 10),
      new THREE.LineBasicMaterial({ color: 0xe9d9ff, transparent: true, opacity: 0.58 }),
    );
    wire.scale.setScalar(1.018);
    core.add(wire);

    const ringMaterials = [
      new THREE.MeshStandardMaterial({ color: 0xc761b3, metalness: 0.68, roughness: 0.24, transparent: true, opacity: 0.68 }),
      new THREE.MeshStandardMaterial({ color: 0x8061bd, metalness: 0.62, roughness: 0.28, transparent: true, opacity: 0.52 }),
      new THREE.MeshStandardMaterial({ color: 0x7698cb, metalness: 0.58, roughness: 0.3, transparent: true, opacity: 0.42 }),
    ];
    rings = ringMaterials.map((material, index) => {
      const ring = new THREE.Mesh(new THREE.TorusGeometry(0.98 + index * 0.12, 0.012, 8, 88), material);
      if (index === 0) ring.rotation.set(0.82, 0.22, 0.08);
      if (index === 1) ring.rotation.set(1.16, -0.62, 0.76);
      if (index === 2) ring.rotation.set(-0.34, 0.78, -0.94);
      sculpture.add(ring);
      return ring;
    });

    const nodeMaterial = new THREE.MeshStandardMaterial({
      color: 0xe7a0d7,
      emissive: 0x713d91,
      emissiveIntensity: 0.72,
      metalness: 0.35,
      roughness: 0.22,
    });
    nodes = new THREE.Group();
    sculpture.add(nodes);
    for (let index = 0; index < 7; index += 1) {
      const angle = (Math.PI * 2 * index) / 7;
      const node = new THREE.Mesh(new THREE.SphereGeometry(index % 3 === 0 ? 0.045 : 0.026, 12, 10), nodeMaterial);
      node.position.set(Math.cos(angle) * 1.2, Math.sin(angle) * 0.72, (index % 2 ? 0.25 : -0.18));
      nodes.add(node);
    }
  }

  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  camera.aspect = width / height;
  camera.position.z = isLanding ? 9.1 : (isRibbon ? 8.4 : 6.5);
  camera.updateProjectionMatrix();
  renderer.setSize(width, height, false);

  let inView = false;
  let visible = false;
  let animationFrame = 0;
  let lastFrame = 0;
  let elapsed = 0;

  const draw = (time = 0) => {
    elapsed = time * 0.001;
    const motionTime = elapsed * (motionPreference.matches ? 0.68 : 1);
    sculpture.rotation.y = Math.sin(motionTime * 0.22) * 0.14;
    sculpture.rotation.x = Math.sin(motionTime * 0.18) * 0.08;
    if (isRibbon) {
      sculpture.rotation.y = Math.sin(motionTime * 0.12) * 0.075;
      sculpture.rotation.x = Math.sin(motionTime * 0.15) * 0.04;
      updateRibbon(motionTime);
      if (ribbon) ribbon.rotation.z = Math.sin(motionTime * 0.2) * 0.018;
      if (pixels) pixels.rotation.y = Math.sin(motionTime * 0.08) * 0.018;
    } else {
      core.rotation.y = elapsed * 0.16;
      core.rotation.x = elapsed * 0.11;
      nodes.rotation.y = -elapsed * 0.12;
      rings[0].rotation.z += 0.0009;
      rings[1].rotation.x -= 0.0006;
      rings[2].rotation.y += 0.0007;
    }
    renderer.render(scene, camera);
  };

  const animate = (time) => {
    animationFrame = 0;
    if (!visible || document.hidden || (motionPreference.matches && !isLanding)) return;
    if (time - lastFrame < 32) {
      animationFrame = window.requestAnimationFrame(animate);
      return;
    }
    lastFrame = time;
    draw(time);
    animationFrame = window.requestAnimationFrame(animate);
  };

  const setActive = (active) => {
    if (typeof active === 'boolean') inView = active;
    visible = inView && !document.hidden;
    if (!visible && animationFrame) {
      window.cancelAnimationFrame(animationFrame);
      animationFrame = 0;
    }
    if (!visible) return;
    draw(performance.now());
    if ((!motionPreference.matches || isLanding) && !document.hidden && !animationFrame) {
      animationFrame = window.requestAnimationFrame(animate);
    }
  };

  const resize = () => {
    const nextWidth = canvas.clientWidth;
    const nextHeight = canvas.clientHeight;
    if (nextWidth < 2 || nextHeight < 2) return;
    camera.aspect = nextWidth / nextHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(nextWidth, nextHeight, false);
    if (visible) draw(performance.now());
  };
  const resizeObserver = new ResizeObserver(resize);
  resizeObserver.observe(canvas);

  const visibilityObserver = new IntersectionObserver((entries) => {
    setActive(entries.some((entry) => entry.isIntersecting));
  }, { threshold: 0.01 });
  visibilityObserver.observe(canvas);

  document.addEventListener('visibilitychange', () => setActive());
  motionPreference.addEventListener?.('change', () => setActive());
  canvas.addEventListener('webglcontextlost', () => {
    setActive(false);
    canvas.dataset.threeUnavailable = 'true';
  }, { once: true });
}

async function observeCanvas(canvas) {
  if (!('IntersectionObserver' in window)
      || (!('WebGLRenderingContext' in window) && !('WebGL2RenderingContext' in window))) {
    canvas.dataset.threeUnavailable = 'true';
    return;
  }
  const loadWhenVisible = async (entries, observer) => {
    if (!entries.some((entry) => entry.isIntersecting)) return;
    observer.disconnect();
    try {
      THREE = THREE || await loadThree();
      createScene(canvas, THREE);
    } catch {
      canvas.dataset.threeUnavailable = 'true';
    }
  };
  const observer = new IntersectionObserver(loadWhenVisible, { threshold: 0.01 });
  observer.observe(canvas);
}

sceneCanvases.forEach(observeCanvas);
