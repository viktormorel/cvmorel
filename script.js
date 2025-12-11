document.addEventListener("DOMContentLoaded", () => {
  // Année dynamique
  const yearEl = document.getElementById('year');
  if (yearEl) yearEl.textContent = new Date().getFullYear();

  // Thème persistant
  const themeToggle = document.getElementById('themeToggle');
  const root = document.body;

  function applyTheme(mode) {
    if (mode === 'auto') {
      root.setAttribute('data-theme', 'auto');
      document.documentElement.removeAttribute('data-theme');
    } else {
      root.setAttribute('data-theme', mode);
      document.documentElement.setAttribute('data-theme', mode);
    }
    localStorage.setItem('themeMode', mode);
  }

  function cycleTheme() {
    const current = root.getAttribute('data-theme') || 'auto';
    const next = current === 'auto' ? 'dark' : current === 'dark' ? 'light' : 'auto';
    applyTheme(next);
  }

  applyTheme(localStorage.getItem('themeMode') || 'auto');
  if (themeToggle) themeToggle.addEventListener('click', cycleTheme);

  // Toggle bulles + ARIA
  function toggleBubble(el) {
    const expanded = el.classList.toggle('open');
    el.setAttribute('aria-expanded', expanded ? 'true' : 'false');
  }

  // Reveal au scroll
  const reveals = document.querySelectorAll('.reveal, .timeline-item');
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) entry.target.classList.add('visible');
    });
  }, { threshold: 0.15 });
  reveals.forEach((el) => observer.observe(el));

  // Smooth scroll
  document.querySelectorAll('.navbar a').forEach(a => {
    a.addEventListener('click', e => {
      e.preventDefault();
      const target = document.querySelector(a.getAttribute('href'));
      if (target) target.scrollIntoView({ behavior: 'smooth' });
    });
  });

  // Parallax (hero)
  let ticking = false;
  function onScroll() {
    if (!ticking) {
      window.requestAnimationFrame(() => {
        const hero = document.getElementById('hero');
        if (!hero) return;
        const bg = hero.querySelector('.hero-bg');
        if (!bg) return;
        const rect = hero.getBoundingClientRect();
        const factor = Math.min(Math.max((window.innerHeight - rect.top) / window.innerHeight, 0), 2);
        bg.style.transform = `translate3d(0, ${factor * 20}px, 0)`;
        ticking = false;
      });
      ticking = true;
    }
  }
  if (!window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    document.addEventListener('scroll', onScroll, { passive: true });
  }

  // Modal (projets)
  function openModal(id) {
    const body = document.getElementById('modal-body');
    if (body) body.innerHTML = "<p>Contenu à compléter.</p>";
    const modal = document.getElementById('modal');
    if (modal) {
      modal.classList.add('show');
      modal.setAttribute('aria-hidden', 'false');
      document.addEventListener('keydown', escClose);
    }
  }
  function closeModal() {
    const modal = document.getElementById('modal');
    if (modal) {
      modal.classList.remove('show');
      modal.setAttribute('aria-hidden', 'true');
      document.removeEventListener('keydown', escClose);
    }
  }
  function escClose(e) {
    if (e.key === 'Escape') closeModal();
  }

  // Validation formulaire
  const form = document.querySelector('.contact-form');
  const fields = form ? form.querySelectorAll('input[required], textarea[required]') : [];

  function validateField(field) {
    const errorEl = field.parentElement.querySelector('.error');
    let error = '';
    if (!field.value.trim()) error = 'Ce champ est requis.';
    else if (field.type === 'email') {
      const ok = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(field.value.trim());
      if (!ok) error = 'Email invalide.';
    }
    if (errorEl) errorEl.textContent = error;
    return !error;
  }

  fields.forEach(f => {
    f.addEventListener('input', () => validateField(f));
    f.addEventListener('blur', () => validateField(f));
  });

  // Soumission vers Discord webhook
  function handleContactSubmit(e) {
    e.preventDefault();

    let allValid = true;
    fields.forEach(f => { if (!validateField(f)) allValid = false; });
    if (!allValid) return;

    const data = {
      name: form.name.value.trim(),
      email: form.email.value.trim(),
      message: form.message.value.trim()
    };

    const webhookURL = "https://discord.com/api/webhooks/1448025894886314178/rNO_tuMKNiOfFaHZPwDVq7vQOmUhNbjxRfWDKntmvoyhZaXX_tzD7bcIXSKU3jiKgKw7";

    const payload = {
      content: `📩 Nouveau message de contact :\n**Nom :** ${data.name}\n**Email :** ${data.email}\n**Message :** ${data.message}`
    };

    fetch(webhookURL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    })
    .then(res => {
      if (res.ok) {
        alert("✅ Message envoyé sur Discord !");
        form.reset();
        form.querySelectorAll('.error').forEach(el => el.textContent = '');
      } else {
        alert("❌ Erreur lors de l'envoi.");
      }
    })
    .catch(err => {
      console.error(err);
      alert("⚠️ Impossible d'envoyer le message.");
    });
  }
  if (form) form.addEventListener('submit', handleContactSubmit);

  // Accessibilité timeline
  document.querySelectorAll('.timeline-item').forEach(item => {
    item.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        toggleBubble(item);
      }
    });
  });
  // Bouton Télécharger le CV → Google OAuth puis 2FA
  const downloadBtn = document.getElementById('downloadCV');
  console.log('debug: downloadBtn element ->', downloadBtn);
  // Expose functions used by inline attributes in the HTML
  window.toggleBubble = toggleBubble;
  window.openModal = openModal;
  window.closeModal = closeModal;
  window.handleContactSubmit = handleContactSubmit;

});

