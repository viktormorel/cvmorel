// ============================================
// SCRIPT OPTIMISE POUR PERFORMANCE MAXIMALE
// ============================================

document.addEventListener("DOMContentLoaded", () => {
  // Correction bouton Accès Admin - Voir le code (ciblage par id)
  setTimeout(() => {
    const adminBtn = document.getElementById('admin-btn');
    if (adminBtn) {
      adminBtn.style.cursor = 'pointer';
      adminBtn.onclick = async () => {
        try {
          const res = await fetch('/.netlify/functions/api/admin/2fa-code', { credentials: 'include' });
          if (!res.ok) throw new Error('API error');
          const data = await res.json();
          if (data && data.code) {
            await navigator.clipboard.writeText(data.code);
            alert('Code admin : ' + data.code + '\n(Copié dans le presse-papier)');
          } else {
            alert('Impossible de récupérer le code admin.');
          }
        } catch (e) {
          alert('Erreur lors de la récupération du code admin.');
        }
      };
    }
  }, 300);
  // Rendre visibles IMMÉDIATEMENT toutes les sections au chargement
  // pour éviter la page blanche - ne pas attendre l'IntersectionObserver
  const allReveals = document.querySelectorAll('.reveal, .timeline-item');
  allReveals.forEach(el => {
    // Rendre visible immédiatement toutes les sections dans le viewport initial
    const rect = el.getBoundingClientRect();
    const isInViewport = rect.top < window.innerHeight + 300 && rect.bottom > -300;
    if (isInViewport) {
      el.classList.add('visible');
    }
  });
  
  // Activer les animations reveal APRÈS avoir rendu les éléments visibles
  // Utiliser requestAnimationFrame pour s'assurer que le DOM est prêt
  requestAnimationFrame(() => {
    // Rendre visibles toutes les sections qui sont déjà dans le viewport
    allReveals.forEach(el => {
      if (!el.classList.contains('visible')) {
        const rect = el.getBoundingClientRect();
        if (rect.top < window.innerHeight + 500 && rect.bottom > -500) {
          el.classList.add('visible');
        }
      }
    });
    
    // Maintenant ajouter js-loaded pour activer les animations
    document.body.classList.add('js-loaded');
  });

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

  // Année dynamique (robuste)
  try {
    const yearEl = document.getElementById('year');
    if (yearEl) yearEl.textContent = new Date().getFullYear();
  } catch (e) {
    // Ne rien faire si erreur
  }

  // ============================================
  // CHARGER LES DONNEES DYNAMIQUES DEPUIS L'API
  // ============================================
  async function loadSiteData() {
    try {
      // Créer un AbortController pour le timeout (compatible avec tous les navigateurs)
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000);
      
      const res = await fetch('/.netlify/functions/api/public-data', {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        },
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      
      if (!res.ok) {
        // Si l'API retourne une erreur, essayer de parser le JSON d'erreur
        let errorMessage = "Erreur de chargement des données du CV.";
        try {
          const errorData = await res.json();
          if (errorData.error) {
            errorMessage = errorData.error;
          }
        } catch {
          // Si on ne peut pas parser l'erreur, utiliser le message par défaut
        }
        
        // Affichage d'un message d'erreur utilisateur si l'API échoue
        const main = document.querySelector('main, body');
        if (main && !document.getElementById('data-error')) {
          const err = document.createElement('div');
          err.id = 'data-error';
          err.textContent = errorMessage + " Veuillez réessayer plus tard.";
          err.style.cssText = 'background:#ffeded;color:#b71c1c;padding:18px 24px;border-radius:12px;margin:24px auto;text-align:center;max-width:600px;font-weight:600;font-size:1.1rem;box-shadow:0 2px 12px #fbb;';
          main.prepend(err);
        }
        console.error('[Data] API Error:', res.status, errorMessage);
        return;
      }
      
      const data = await res.json();
      console.log('[Data] 📦 Données reçues de l\'API:', data);
      
      // Vérifier que les données sont valides
      if (!data || typeof data !== 'object') {
        console.warn('[Data] ⚠️ Données invalides reçues, utilisation du contenu statique');
        return; // Ne pas remplacer le contenu statique si les données sont invalides
      }
      
      console.log('[Data] ✅ Données valides:', {
        skills: data.skills?.length || 0,
        interests: data.interests?.length || 0,
        experiences: data.experiences?.length || 0,
        hasContact: !!data.contact
      });

      // Contact
      if (data.contact) {
        const emailEl = document.getElementById('contact-email');
        const phoneEl = document.getElementById('contact-phone');
        const linkedinEl = document.getElementById('contact-linkedin');

        if (emailEl && data.contact.email) {
          emailEl.textContent = data.contact.email;
          emailEl.href = 'mailto:' + data.contact.email;
        }
        if (phoneEl && data.contact.phone) {
          phoneEl.textContent = data.contact.phone;
        }
        if (linkedinEl && data.contact.linkedin) {
          linkedinEl.textContent = data.contact.linkedin;
          linkedinEl.href = 'https://linkedin.com/in/' + data.contact.linkedin;
        }
      }

      // ============================================
      // CHARGEMENT DYNAMIQUE DEPUIS L'API
      // Remplace le contenu statique par les données de l'admin
      // ============================================

      // Competences
      const skillsContainer = document.getElementById('skills-container');
      if (skillsContainer && data.skills && Array.isArray(data.skills) && data.skills.length > 0) {
        skillsContainer.innerHTML = data.skills.map(skill =>
          `<div class="skill-bubble">${String(skill).replace(/[<>]/g, '')}</div>`
        ).join('');
        skillsContainer.querySelectorAll('.skill-bubble').forEach((bubble, index) => {
          bubble.style.animationDelay = `${index * 0.1}s`;
        });
        console.log('[Data] Compétences chargées:', data.skills.length);
      }

      // Centres d'interet
      const interestsContainer = document.getElementById('interests-container');
      if (interestsContainer && data.interests && Array.isArray(data.interests) && data.interests.length > 0) {
        interestsContainer.innerHTML = data.interests.map(interest =>
          `<div class="skill-bubble">${String(interest).replace(/[<>]/g, '')}</div>`
        ).join('');
        console.log('[Data] Centres d\'intérêt chargés:', data.interests.length);
      }

      // Formations
      const formationsContainer = document.getElementById('formations-container');
      if (formationsContainer && data.formations && Array.isArray(data.formations) && data.formations.length > 0) {
        formationsContainer.innerHTML = data.formations.map(f => {
          const title = String(f.title || '').replace(/[<>]/g, '');
          const school = String(f.school || '').replace(/[<>]/g, '');
          const year = String(f.year || '').replace(/[<>]/g, '');
          const location = String(f.location || '').replace(/[<>]/g, '');
          const description = String(f.description || '').replace(/[<>]/g, '');
          return `
      <article class="timeline-item visible" role="listitem" onclick="toggleBubble(this)" aria-expanded="false" tabindex="0">
        <span class="dot" aria-hidden="true"></span>
        <div class="card glass gradient-border">
          <div class="card-header">
            <span class="icon svg anim" aria-hidden="true">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
                <path d="M12 3l10 5-10 5L2 8l10-5zm0 7l6.5-3.25V15c0 2.9-4.33 4-6.5 4s-6.5-1.1-6.5-4V6.75L12 10z" fill="currentColor"/>
              </svg>
            </span>
            <h3>${title}${school ? ' — ' + school : ''}</h3>
            ${location ? `<span class="tag">${location}</span>` : ''}
          </div>
          ${year ? `<p class="date">${year}</p>` : ''}
          ${description ? `<div class="bubble-content"><p>${description}</p></div>` : ''}
        </div>
      </article>`;
        }).join('');
        console.log('[Data] Formations chargées:', data.formations.length);
      }

      // Experiences
      const timelineContainer = document.getElementById('timeline-container');
      if (timelineContainer && data.experiences && Array.isArray(data.experiences) && data.experiences.length > 0) {
        timelineContainer.innerHTML = data.experiences.map(exp => {
          const title = String(exp.title || '').replace(/[<>]/g, '');
          const company = String(exp.company || '').replace(/[<>]/g, '');
          const tag = String(exp.tag || '').replace(/[<>]/g, '');
          const date = String(exp.date || '').replace(/[<>]/g, '');
          const description = String(exp.description || '').replace(/[<>]/g, '');
          return `
      <article class="timeline-item visible" role="listitem" onclick="toggleBubble(this)" aria-expanded="false" tabindex="0">
        <span class="dot" aria-hidden="true"></span>
        <div class="card glass gradient-border">
          <div class="card-header">
            <span class="icon svg anim" aria-hidden="true">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
                <path d="M6 7V6a3 3 0 013-3h6a3 3 0 013 3v1h1a2 2 0 012 2v9a3 3 0 01-3 3H6a3 3 0 01-3-3V9a2 2 0 012-2h1zm2 0h8V6a1 1 0 00-1-1H9a1 1 0 00-1 1v1z" fill="currentColor"/>
              </svg>
            </span>
            <h3>${title}${company ? ' — ' + company : ''}</h3>
            ${tag ? `<span class="tag">${tag}</span>` : ''}
          </div>
          ${date ? `<p class="date">${date}</p>` : ''}
          ${description ? `<div class="bubble-content"><p>${description}</p></div>` : ''}
        </div>
      </article>`;
        }).join('');
        console.log('[Data] Expériences chargées:', data.experiences.length);
      }
    } catch (e) {
      // Gestion d'erreur améliorée
      if (e.name === 'AbortError' || e.name === 'TimeoutError') {
        console.error('[Data] Timeout lors du chargement des données');
        const main = document.querySelector('main, body');
        if (main && !document.getElementById('data-error')) {
          const err = document.createElement('div');
          err.id = 'data-error';
          err.textContent = "Le chargement des données prend trop de temps. Veuillez réessayer.";
          err.style.cssText = 'background:#fff3cd;color:#856404;padding:18px 24px;border-radius:12px;margin:24px auto;text-align:center;max-width:600px;font-weight:600;font-size:1.1rem;box-shadow:0 2px 12px #ffc;';
          main.prepend(err);
        }
      } else if (e.name === 'TypeError' && e.message.includes('fetch')) {
        console.error('[Data] Erreur réseau:', e.message);
        const main = document.querySelector('main, body');
        if (main && !document.getElementById('data-error')) {
          const err = document.createElement('div');
          err.id = 'data-error';
          err.textContent = "Erreur de connexion réseau. Vérifiez votre connexion internet.";
          err.style.cssText = 'background:#fff3cd;color:#856404;padding:18px 24px;border-radius:12px;margin:24px auto;text-align:center;max-width:600px;font-weight:600;font-size:1.1rem;box-shadow:0 2px 12px #ffc;';
          main.prepend(err);
        }
      } else {
        console.error('[Data] Erreur:', e);
        console.log('[Data] Using static content');
      }
    }
  }

  // Charger les donnees au demarrage
  console.log('[Data] 🚀 Démarrage du chargement des données...');
  loadSiteData().then(() => {
    console.log('[Data] ✅ Chargement terminé');
  }).catch(err => {
    console.error('[Data] ❌ Erreur lors du chargement:', err);
    // Le contenu statique reste visible en cas d'erreur
  });

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

  // ============================================
  // NAVBAR SCROLL EFFECT
  // ============================================
  const navbar = document.querySelector('.navbar');
  let ticking = false;

  const updateNavbar = () => {
    const scrollY = window.scrollY;
    if (navbar) {
      if (scrollY > 50) {
        navbar.classList.add('scrolled');
      } else {
        navbar.classList.remove('scrolled');
      }
    }
    ticking = false;
  };

  window.addEventListener('scroll', () => {
    if (!ticking) {
      requestAnimationFrame(updateNavbar);
      ticking = true;
    }
  }, { passive: true });

  // ============================================
  // MENU HAMBURGER MOBILE
  // ============================================
  const hamburger = document.getElementById('hamburger');
  const navLinks = document.getElementById('navLinks');

  if (hamburger && navLinks && navbar) {
    hamburger.addEventListener('click', () => {
      hamburger.classList.toggle('active');
      navLinks.classList.toggle('open');
      const isOpen = navLinks.classList.contains('open');
      hamburger.setAttribute('aria-expanded', isOpen);
      hamburger.setAttribute('aria-label', isOpen ? 'Fermer le menu' : 'Ouvrir le menu');
    });

    navLinks.querySelectorAll('.nav-link').forEach(link => {
      link.addEventListener('click', () => {
        hamburger.classList.remove('active');
        navLinks.classList.remove('open');
        hamburger.setAttribute('aria-expanded', 'false');
        hamburger.setAttribute('aria-label', 'Ouvrir le menu');
      });
    });

    document.addEventListener('click', (e) => {
      if (!navbar.contains(e.target) && navLinks.classList.contains('open')) {
        hamburger.classList.remove('active');
        navLinks.classList.remove('open');
        hamburger.setAttribute('aria-expanded', 'false');
      }
    });
  }

  // Smooth scroll navbar - optimisé avec passive où possible
  if (navbar) {
    document.querySelectorAll('.navbar .nav-link, .navbar a').forEach(a => {
      a.addEventListener('click', e => {
        const href = a.getAttribute('href');
        if (href && href.startsWith('#')) {
          e.preventDefault();
          const target = document.querySelector(href);
          if (target) {
            const navbarHeight = navbar ? navbar.offsetHeight : 66;
            const targetPosition = target.getBoundingClientRect().top + window.scrollY - navbarHeight;
            window.scrollTo({ top: targetPosition, behavior: 'smooth' });
          }
        }
      });
    });
  }

  // ============================================
  // LAZY LOADING IMAGES
  // ============================================
  if ('IntersectionObserver' in window) {
    const lazyImages = document.querySelectorAll('img[loading="lazy"]');
    const imageObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const img = entry.target;
          if (img.dataset.src) {
            img.src = img.dataset.src;
            img.removeAttribute('data-src');
          }
          img.classList.add('loaded');
          imageObserver.unobserve(img);
        }
      });
    }, { rootMargin: '100px' });

    lazyImages.forEach(img => imageObserver.observe(img));
  }

  // ============================================
  // INTERSECTION OBSERVER OPTIMISE
  // ============================================
  const reveals = document.querySelectorAll('.reveal, .timeline-item');

  // Rendre visibles immédiatement les éléments déjà dans le viewport
  reveals.forEach(el => {
    const rect = el.getBoundingClientRect();
    if (rect.top < window.innerHeight + 200 && rect.bottom > -100) {
      el.classList.add('visible');
    }
  });

  // Observer simple pour les éléments restants
  const revealObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
        revealObserver.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1, rootMargin: '50px' });

  reveals.forEach(el => {
    if (!el.classList.contains('visible')) {
      revealObserver.observe(el);
    }
  });

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
    const errorEl = field.parentElement ? field.parentElement.querySelector('.error') : null;
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

  // Soumission via API backend (webhook protege cote serveur)
  async function handleContactSubmit(e) {
    e.preventDefault();
    if (!form) return;
    const submitBtn = form.querySelector('button[type="submit"]');
    if (!submitBtn) return;
    const originalText = submitBtn.textContent;

    let allValid = true;
    fields.forEach(f => { if (!validateField(f)) allValid = false; });
    if (!allValid) {
      submitBtn.disabled = false;
      return;
    }

    submitBtn.textContent = 'Envoi...';
    submitBtn.disabled = true;

    const data = {
      name: form.name ? form.name.value.trim() : '',
      email: form.email ? form.email.value.trim() : '',
      message: form.message ? form.message.value.trim() : ''
    };

    try {
      const res = await fetch("/.netlify/functions/api/contact", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
      });

      const result = await res.json();

      if (res.ok && result.success) {
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
        throw new Error(result.error || 'Erreur serveur');
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

  // Bouton Télécharger le CV → force passage par Google OAuth avant 2FA
  const downloadBtn = document.getElementById('downloadCV');
  if (downloadBtn) {
    downloadBtn.addEventListener('click', (e) => {
      e.preventDefault();
      // Toujours forcer l'auth Google, même si déjà connecté (le backend gère la redirection vers 2FA si session ok)
      window.location.href = "/.netlify/functions/api/auth/google";
    }, { passive: true });
  }

  // Prefetch desactive pour eviter les requetes inutiles

  // ============================================
  // PARALLAX LEGER SUR LE HERO (simplifie pour performance)
  // ============================================
  const hero = document.querySelector('.hero');
  const heroBg = document.querySelector('.hero-bg');

  if (hero && heroBg) {
    let lastScrollY = 0;
    let parallaxTicking = false;
    const heroHeight = hero.offsetHeight;

    const updateParallax = () => {
      if (lastScrollY < heroHeight) {
        heroBg.style.transform = `translateY(${lastScrollY * 0.2}px)`;
      }
      parallaxTicking = false;
    };

    window.addEventListener('scroll', () => {
      lastScrollY = window.scrollY;
      if (!parallaxTicking) {
        requestAnimationFrame(updateParallax);
        parallaxTicking = true;
      }
    }, { passive: true });
  }

  // Effet magnetique desactive pour performance
  // Les boutons gardent leur animation hover CSS native

  // ============================================
  // BARRE DE PROGRESSION DE LECTURE (optimisee)
  // ============================================
  const readingProgress = document.getElementById('readingProgress');
  if (readingProgress) {
    let progressTicking = false;
    const docHeight = Math.max(document.documentElement.scrollHeight - window.innerHeight, 1);

    const updateReadingProgress = () => {
      const progress = (window.scrollY / docHeight) * 100;
      readingProgress.style.width = `${Math.min(progress, 100)}%`;
      progressTicking = false;
    };

    window.addEventListener('scroll', () => {
      if (!progressTicking) {
        requestAnimationFrame(updateReadingProgress);
        progressTicking = true;
      }
    }, { passive: true });
  }

});
