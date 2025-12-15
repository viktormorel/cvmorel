// ============================================
// SCRIPT OPTIMISE POUR PERFORMANCE MAXIMALE
// ============================================

document.addEventListener("DOMContentLoaded", () => {
  // Tracker la visite uniquement sur la page d'accueil (une seule fois par jour)
  const isHomePage = window.location.pathname === '/' || window.location.pathname === '/index.html';
  const lastVisit = localStorage.getItem('lastVisit');
  const today = new Date().toDateString();
  if (isHomePage && lastVisit !== today) {
    // Utiliser sendBeacon pour ne pas bloquer le thread principal
    if (navigator.sendBeacon) {
      navigator.sendBeacon('/.netlify/functions/api/track-visit');
    } else {
      fetch('/.netlify/functions/api/track-visit', { method: 'POST' }).catch(() => {});
    }
    localStorage.setItem('lastVisit', today);
  }

  // Année dynamique
  const yearEl = document.getElementById('year');
  if (yearEl) yearEl.textContent = new Date().getFullYear();

  // Thème persistant (auto/dark/light) - appliqué immédiatement
  const themeToggle = document.getElementById('themeToggle');
  function applyTheme(mode) {
    if (mode === 'auto') {
      document.documentElement.removeAttribute('data-theme');
    } else {
      document.documentElement.setAttribute('data-theme', mode);
    }
    localStorage.setItem('themeMode', mode);
  }
  function cycleTheme() {
    const current = document.documentElement.getAttribute('data-theme') || 'auto';
    const next = current === 'auto' ? 'dark' : current === 'dark' ? 'light' : 'auto';
    applyTheme(next);
  }
  applyTheme(localStorage.getItem('themeMode') || 'auto');
  if (themeToggle) themeToggle.addEventListener('click', cycleTheme, { passive: true });

  // Smooth scroll navbar - optimisé avec passive où possible
  document.querySelectorAll('.navbar a').forEach(a => {
    a.addEventListener('click', e => {
      const href = a.getAttribute('href');
      if (href && href.startsWith('#')) {
        e.preventDefault();
        const target = document.querySelector(href);
        if (target) {
          target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      }
    });
  });

  // ============================================
  // INTERSECTION OBSERVER OPTIMISE
  // ============================================
  const reveals = document.querySelectorAll('.reveal, .timeline-item');

  // Options optimisées pour un déclenchement anticipé
  const observerOptions = {
    threshold: 0.05,
    rootMargin: '100px 0px 50px 0px' // Pré-charge 100px avant le viewport
  };

  const revealObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        // Utiliser requestIdleCallback si disponible, sinon RAF
        const reveal = () => entry.target.classList.add('visible');
        if ('requestIdleCallback' in window) {
          requestIdleCallback(reveal, { timeout: 100 });
        } else {
          requestAnimationFrame(reveal);
        }
        revealObserver.unobserve(entry.target);
      }
    });
  }, observerOptions);

  reveals.forEach(el => revealObserver.observe(el));

  // ============================================
  // MODAL OPTIMISE
  // ============================================
  const modal = document.getElementById('modal');
  const modalBody = document.getElementById('modal-body');

  function openModal(id) {
    if (modalBody) modalBody.innerHTML = "<p>Contenu à compléter.</p>";
    if (modal) {
      modal.classList.add('show');
      modal.setAttribute('aria-hidden', 'false');
      document.addEventListener('keydown', escClose);
    }
  }
  function closeModal() {
    if (modal) {
      modal.classList.remove('show');
      modal.setAttribute('aria-hidden', 'true');
      document.removeEventListener('keydown', escClose);
    }
  }
  function escClose(e) { if (e.key === 'Escape') closeModal(); }
  window.openModal = openModal;
  window.closeModal = closeModal;

  // ============================================
  // VALIDATION FORMULAIRE OPTIMISEE
  // ============================================
  const form = document.querySelector('.contact-form');
  const fields = form ? form.querySelectorAll('input[required], textarea[required]') : [];
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

  function validateField(field) {
    const errorEl = field.parentElement.querySelector('.error');
    let error = '';
    const value = field.value.trim();
    if (!value) {
      error = 'Ce champ est requis.';
    } else if (field.type === 'email' && !emailRegex.test(value)) {
      error = 'Email invalide.';
    }
    if (errorEl) errorEl.textContent = error;
    return !error;
  }

  // Debounce optimisé
  function debounce(fn, delay) {
    let timer;
    return function(...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), delay);
    };
  }

  const debouncedValidate = debounce((field) => validateField(field), 200);

  fields.forEach(f => {
    f.addEventListener('input', () => debouncedValidate(f), { passive: true });
    f.addEventListener('blur', () => validateField(f), { passive: true });
  });

  // Soumission vers Discord webhook avec feedback visuel
  async function handleContactSubmit(e) {
    e.preventDefault();

    const submitBtn = form.querySelector('button[type="submit"]');
    const originalText = submitBtn.textContent;

    let allValid = true;
    fields.forEach(f => { if (!validateField(f)) allValid = false; });
    if (!allValid) return;

    // Feedback visuel
    submitBtn.textContent = 'Envoi...';
    submitBtn.disabled = true;

    const data = {
      name: form.name.value.trim(),
      email: form.email.value.trim(),
      message: form.message.value.trim()
    };
    const payload = {
      content: `📩 Nouveau message :\n**Nom :** ${data.name}\n**Email :** ${data.email}\n**Message :** ${data.message}`
    };

    try {
      const res = await fetch("https://discord.com/api/webhooks/1448025894886314178/rNO_tuMKNiOfFaHZPwDVq7vQOmUhNbjxRfWDKntmvoyhZaXX_tzD7bcIXSKU3jiKgKw7", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      if (res.ok) {
        submitBtn.textContent = '✓ Envoyé !';
        submitBtn.style.background = 'linear-gradient(135deg, #3ddc97, #16c79a)';
        form.reset();
        form.querySelectorAll('.error').forEach(el => el.textContent = '');
        setTimeout(() => {
          submitBtn.textContent = originalText;
          submitBtn.style.background = '';
          submitBtn.disabled = false;
        }, 2500);
      } else {
        throw new Error('Erreur serveur');
      }
    } catch (err) {
      console.error(err);
      submitBtn.textContent = '✗ Erreur';
      submitBtn.style.background = 'linear-gradient(135deg, #ff6b6b, #ee5a24)';
      setTimeout(() => {
        submitBtn.textContent = originalText;
        submitBtn.style.background = '';
        submitBtn.disabled = false;
      }, 2000);
    }
  }
  if (form) form.addEventListener('submit', handleContactSubmit);

  // ============================================
  // TOGGLE BUBBLE OPTIMISE
  // ============================================
  function toggleBubble(el) {
    requestAnimationFrame(() => {
      const isOpen = el.classList.toggle('open');
      el.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    });
  }
  window.toggleBubble = toggleBubble;

  // ============================================
  // COPIER AVEC FEEDBACK AMELIORE
  // ============================================
  function copyToClipboard(text, btn) {
    navigator.clipboard.writeText(text).then(() => {
      const originalTitle = btn.title;
      btn.title = 'Copié !';
      btn.classList.add('copied');

      // Animation de feedback
      btn.style.transform = 'scale(1.2)';
      setTimeout(() => {
        btn.style.transform = '';
      }, 150);

      setTimeout(() => {
        btn.title = originalTitle;
        btn.classList.remove('copied');
      }, 2000);
    }).catch(() => {
      // Fallback pour navigateurs anciens
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      btn.classList.add('copied');
      setTimeout(() => btn.classList.remove('copied'), 2000);
    });
  }

  function copyEmail(e) {
    copyToClipboard('viktormorel@mailo.com', e.currentTarget);
  }
  window.copyEmail = copyEmail;

  function copyPhone(e) {
    copyToClipboard('0614099355', e.currentTarget);
  }
  window.copyPhone = copyPhone;

  function copyLinkedin(e) {
    copyToClipboard('viktormorel', e.currentTarget);
  }
  window.copyLinkedin = copyLinkedin;

  // Accessibilité timeline (clavier) - event delegation
  document.addEventListener('keydown', e => {
    if (e.target.classList.contains('timeline-item') && (e.key === 'Enter' || e.key === ' ')) {
      e.preventDefault();
      toggleBubble(e.target);
    }
  });

  // Bouton Télécharger le CV → déclenche OAuth + 2FA
  const downloadBtn = document.getElementById('downloadCV');
  if (downloadBtn) {
    downloadBtn.addEventListener('click', () => {
      window.location.href = "/.netlify/functions/api/auth/google";
    }, { passive: true });
  }

  // ============================================
  // PREFETCH LIENS AU SURVOL (performance)
  // ============================================
  if ('IntersectionObserver' in window) {
    const prefetchLinks = document.querySelectorAll('a[href^="/"]');
    prefetchLinks.forEach(link => {
      link.addEventListener('mouseenter', () => {
        const href = link.getAttribute('href');
        if (href && !document.querySelector(`link[href="${href}"]`)) {
          const prefetch = document.createElement('link');
          prefetch.rel = 'prefetch';
          prefetch.href = href;
          document.head.appendChild(prefetch);
        }
      }, { once: true, passive: true });
    });
  }

  // ============================================
  // PARALLAX LEGER SUR LE HERO
  // ============================================
  const hero = document.querySelector('.hero');
  const heroBg = document.querySelector('.hero-bg');
  const avatar = document.querySelector('.avatar');

  if (hero && heroBg) {
    let ticking = false;

    const updateParallax = () => {
      const scrollY = window.scrollY;
      const heroHeight = hero.offsetHeight;

      if (scrollY < heroHeight) {
        const parallaxOffset = scrollY * 0.3;
        const opacity = 1 - (scrollY / heroHeight) * 0.5;

        heroBg.style.transform = `translateY(${parallaxOffset}px) translateZ(0)`;

        if (avatar) {
          avatar.style.transform = `translateY(${scrollY * 0.15}px) translateZ(0)`;
          avatar.style.opacity = opacity;
        }
      }
      ticking = false;
    };

    window.addEventListener('scroll', () => {
      if (!ticking) {
        requestAnimationFrame(updateParallax);
        ticking = true;
      }
    }, { passive: true });
  }

  // ============================================
  // CURSEUR MAGNETIQUE SUR LES BOUTONS
  // ============================================
  const magneticBtns = document.querySelectorAll('.btn.primary');

  magneticBtns.forEach(btn => {
    btn.addEventListener('mousemove', (e) => {
      const rect = btn.getBoundingClientRect();
      const x = e.clientX - rect.left - rect.width / 2;
      const y = e.clientY - rect.top - rect.height / 2;

      btn.style.transform = `translate(${x * 0.15}px, ${y * 0.15}px) scale(1.02)`;
    }, { passive: true });

    btn.addEventListener('mouseleave', () => {
      btn.style.transform = '';
    }, { passive: true });
  });

  // ============================================
  // EFFET STAGGER SUR LES SKILL BUBBLES
  // ============================================
  const skillBubbles = document.querySelectorAll('.skill-bubble');
  skillBubbles.forEach((bubble, index) => {
    bubble.style.animationDelay = `${index * 0.1}s`;
  });
});
