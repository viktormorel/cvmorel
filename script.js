document.addEventListener("DOMContentLoaded", () => {
  // Année dynamique
  const yearEl = document.getElementById('year');
  if (yearEl) yearEl.textContent = new Date().getFullYear();

  // Thème persistant (auto/dark/light)
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
  if (themeToggle) themeToggle.addEventListener('click', cycleTheme);

  // Smooth scroll navbar - optimise avec passive
  document.querySelectorAll('.navbar a').forEach(a => {
    a.addEventListener('click', e => {
      const href = a.getAttribute('href');
      if (href && href.startsWith('#')) {
        e.preventDefault();
        const target = document.querySelector(href);
        if (target) target.scrollIntoView({ behavior: 'smooth' });
      }
    }, { passive: false });
  });

  // Reveal au scroll - optimise avec rootMargin pour pre-charger
  const reveals = document.querySelectorAll('.reveal, .timeline-item');
  const observerOptions = {
    threshold: 0.1,
    rootMargin: '50px 0px'
  };
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        requestAnimationFrame(() => {
          entry.target.classList.add('visible');
        });
        observer.unobserve(entry.target);
      }
    });
  }, observerOptions);
  reveals.forEach(el => observer.observe(el));

  // Modal projets - cache les elements
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

  // Validation formulaire contact - debounce pour performance
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

  // Debounce pour eviter trop de validations
  function debounce(fn, delay) {
    let timer;
    return function(...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), delay);
    };
  }

  const debouncedValidate = debounce((field) => validateField(field), 150);

  fields.forEach(f => {
    f.addEventListener('input', () => debouncedValidate(f), { passive: true });
    f.addEventListener('blur', () => validateField(f), { passive: true });
  });

  // Soumission vers Discord webhook
  async function handleContactSubmit(e) {
    e.preventDefault();
    let allValid = true;
    fields.forEach(f => { if (!validateField(f)) allValid = false; });
    if (!allValid) return;

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
        alert("✅ Message envoyé !");
        form.reset();
        form.querySelectorAll('.error').forEach(el => el.textContent = '');
      } else {
        alert("❌ Erreur lors de l'envoi.");
      }
    } catch (err) {
      console.error(err);
      alert("⚠️ Impossible d'envoyer le message.");
    }
  }
  if (form) form.addEventListener('submit', handleContactSubmit);

  // Toggle bubble pour les timeline items - optimise avec RAF
  function toggleBubble(el) {
    requestAnimationFrame(() => {
      el.classList.toggle('open');
      el.setAttribute('aria-expanded', el.classList.contains('open') ? 'true' : 'false');
    });
  }
  window.toggleBubble = toggleBubble;

  // Accessibilité timeline (clavier)
  document.querySelectorAll('.timeline-item').forEach(item => {
    item.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        toggleBubble(item);
      }
    });
  });

  // Bouton Télécharger le CV → déclenche OAuth + 2FA
  const downloadBtn = document.getElementById('downloadCV');
  if (downloadBtn) {
    downloadBtn.addEventListener('click', () => {
      window.location.href = "/.netlify/functions/api/auth/google";
    });
  }
});
