import express from 'express';
import http from 'node:http';
import cookieParser from 'cookie-parser';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { db } from './server/db.ts';
import { hashPassword, verifyPassword, generateToken, authenticateToken, AuthenticatedRequest } from './server/auth.ts';
import { aiEngine } from './server/ai/provider.ts';
import { setupLiveWebSocket } from './server/ai/live.ts';
import { scienceService } from './server/science.ts';
import { Conversation, Message, RyxiaMode } from './src/types/index.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// --- Health / Info ---
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', app: 'RYXIA', signature: 'RYXIA — by Adan', version: '1.0.0 Pro' });
});

// --- Auth Routes ---
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Tous les champs sont requis.' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Le mot de passe doit comporter au moins 6 caractères.' });
    }

    const existing = db.findUserByEmail(email);
    if (existing) {
      return res.status(409).json({ error: 'Un compte avec cette adresse email existe déjà.' });
    }

    const passwordHash = await hashPassword(password);
    const userId = `usr_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const newUser = db.createUser({
      id: userId,
      name: name.trim(),
      email: email.trim().toLowerCase(),
      passwordHash,
      createdAt: new Date().toISOString(),
      avatar: `https://api.dicebear.com/7.x/shapes/svg?seed=${encodeURIComponent(email)}`,
    });

    const token = generateToken(newUser);
    res.cookie('ryxia_token', token, {
      httpOnly: false,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    return res.status(201).json({
      token,
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        avatar: newUser.avatar,
        createdAt: newUser.createdAt,
      },
    });
  } catch (err: any) {
    console.error('Register error:', err);
    return res.status(500).json({ error: 'Erreur serveur lors de la création du compte.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email et mot de passe requis.' });
    }

    const user = db.findUserByEmail(email);
    if (!user) {
      return res.status(401).json({ error: 'Identifiants incorrects.' });
    }

    const isValid = await verifyPassword(password, user.passwordHash);
    if (!isValid) {
      return res.status(401).json({ error: 'Identifiants incorrects.' });
    }

    const token = generateToken(user);
    res.cookie('ryxia_token', token, {
      httpOnly: false,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    return res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        createdAt: user.createdAt,
      },
    });
  } catch (err: any) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Erreur serveur lors de la connexion.' });
  }
});

app.post('/api/auth/guest', async (req, res) => {
  try {
    const guestId = `guest_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const guestEmail = 'invite@ryxia.app';
    const passwordHash = await hashPassword('ryxia_guest_pass');

    const newUser = db.createUser({
      id: guestId,
      name: 'Invité RYXIA',
      email: guestEmail,
      passwordHash,
      createdAt: new Date().toISOString(),
      avatar: `https://api.dicebear.com/7.x/shapes/svg?seed=${guestId}`,
    });

    const token = generateToken(newUser);
    res.cookie('ryxia_token', token, {
      httpOnly: false,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    return res.status(201).json({
      token,
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        avatar: newUser.avatar,
        createdAt: newUser.createdAt,
      },
      isGuest: true,
    });
  } catch (err: any) {
    console.error('Guest auth error:', err);
    return res.status(500).json({ error: 'Erreur création session invitée' });
  }
});

// Firebase Auth Google Sign-in Sync Endpoint
app.post('/api/auth/firebase-sync', async (req, res) => {
  try {
    const { uid, email, name, avatar } = req.body;
    if (!uid) {
      return res.status(400).json({ error: 'UID Firebase manquant.' });
    }

    let user = db.findUserById(uid);
    if (!user) {
      const passwordHash = await hashPassword(`fb_secret_${uid}`);
      user = db.createUser({
        id: uid,
        name: name || (email ? email.split('@')[0] : 'Utilisateur Google'),
        email: email || `${uid}@firebase.user`,
        passwordHash,
        avatar: avatar || `https://api.dicebear.com/7.x/shapes/svg?seed=${uid}`,
        createdAt: new Date().toISOString(),
      });
    } else if (name || avatar) {
      db.updateUserProfile(uid, { name, avatar });
      user = db.findUserById(uid);
    }

    if (!user) {
      return res.status(500).json({ error: 'Erreur lors de la création du profil utilisateur.' });
    }

    const token = generateToken(user);
    res.cookie('ryxia_token', token, {
      httpOnly: false,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    const stats = db.getUserStats(user.id);
    const settings = db.getSettings(user.id);

    return res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        createdAt: user.createdAt,
      },
      stats,
      settings,
    });
  } catch (err: any) {
    console.error('Firebase sync error:', err);
    return res.status(500).json({ error: 'Erreur lors de la synchronisation Firebase.' });
  }
});

app.get('/api/auth/me', authenticateToken, (req: AuthenticatedRequest, res) => {
  const user = req.user!;
  const stats = db.getUserStats(user.id);
  const settings = db.getSettings(user.id);

  // Return clean user object without password hash
  return res.json({
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      avatar: user.avatar,
      createdAt: user.createdAt,
    },
    stats,
    settings,
  });
});

app.patch('/api/auth/profile', authenticateToken, (req: AuthenticatedRequest, res) => {
  const user = req.user!;
  const { name, avatar } = req.body;
  const updated = db.updateUserProfile(user.id, { name, avatar });
  return res.json({ user: updated });
});

// --- Conversations Routes ---
app.get('/api/conversations', authenticateToken, (req: AuthenticatedRequest, res) => {
  const userId = req.user!.id;
  const conversations = db.getConversations(userId);
  return res.json({ conversations });
});

app.post('/api/conversations', authenticateToken, (req: AuthenticatedRequest, res) => {
  const userId = req.user!.id;
  const { title, mode } = req.body;

  const validMode: RyxiaMode = ['general', 'code', 'study', 'creative', 'fast'].includes(mode) ? mode : 'general';
  const newConv: Conversation = {
    id: `conv_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    userId,
    title: title ? title.trim() : 'Nouvelle conversation',
    mode: validMode,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  const saved = db.createConversation(newConv);
  return res.status(201).json({ conversation: saved });
});

app.get('/api/conversations/:id', authenticateToken, (req: AuthenticatedRequest, res) => {
  const userId = req.user!.id;
  const { id } = req.params;

  const conversation = db.getConversation(id, userId);
  if (!conversation) {
    return res.status(404).json({ error: 'Conversation non trouvée.' });
  }

  const messages = db.getMessages(id, userId);
  return res.json({ conversation, messages });
});

app.patch('/api/conversations/:id', authenticateToken, (req: AuthenticatedRequest, res) => {
  const userId = req.user!.id;
  const { id } = req.params;
  const { title, mode } = req.body;

  const updated = db.updateConversation(id, userId, { title, mode });
  if (!updated) {
    return res.status(404).json({ error: 'Conversation non trouvée.' });
  }

  return res.json({ conversation: updated });
});

app.delete('/api/conversations/:id', authenticateToken, (req: AuthenticatedRequest, res) => {
  const userId = req.user!.id;
  const { id } = req.params;

  const deleted = db.deleteConversation(id, userId);
  if (!deleted) {
    return res.status(404).json({ error: 'Conversation non trouvée.' });
  }

  return res.json({ success: true });
});

app.delete('/api/conversations', authenticateToken, (req: AuthenticatedRequest, res) => {
  const userId = req.user!.id;
  const count = db.clearAllConversations(userId);
  return res.json({ success: true, count });
});

app.get('/api/conversations/:id/export', authenticateToken, (req: AuthenticatedRequest, res) => {
  const userId = req.user!.id;
  const { id } = req.params;
  const format = req.query.format === 'json' ? 'json' : 'markdown';

  const conv = db.getConversation(id, userId);
  if (!conv) {
    return res.status(404).json({ error: 'Conversation introuvable.' });
  }

  const messages = db.getMessages(id, userId);

  if (format === 'json') {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="ryxia_${conv.id}.json"`);
    return res.send(JSON.stringify({ conversation: conv, messages }, null, 2));
  }

  let md = `# ${conv.title}\n\n`;
  md += `**Date**: ${new Date(conv.createdAt).toLocaleDateString()} | **Mode**: ${conv.mode.toUpperCase()}\n`;
  md += `**Signature**: RYXIA — by Adan\n\n---\n\n`;

  for (const m of messages) {
    md += `### ${m.role === 'user' ? 'Vous' : 'RYXIA (' + m.model + ')'}\n\n`;
    md += `${m.content}\n\n---\n\n`;
  }

  res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="ryxia_${conv.id}.md"`);
  return res.send(md);
});

// --- Image Generation & Editing Routes using gemini-3.1-flash-lite-image ---
app.post('/api/images/generate', authenticateToken, async (req: AuthenticatedRequest, res) => {
  const userId = req.user!.id;
  const { prompt, aspectRatio = '1:1', conversationId } = req.body;

  if (!prompt || typeof prompt !== 'string' || !prompt.trim()) {
    return res.status(400).json({ error: 'Veuillez fournir une description pour générer l\'image.' });
  }

  const userSettings = db.getSettings(userId);

  try {
    const result = await aiEngine.generateImage({
      prompt: prompt.trim(),
      aspectRatio,
      customApiKey: userSettings?.customOpenAiKey,
    });

    // If conversationId provided, record messages in conversation
    if (conversationId) {
      const conv = db.getConversation(conversationId, userId);
      if (conv) {
        // User prompt message
        db.addMessage({
          id: `msg_${Date.now()}_u_img`,
          conversationId: conv.id,
          role: 'user',
          content: `🎨 Créer une image : "${prompt.trim()}" (Ratio ${aspectRatio})`,
          createdAt: new Date().toISOString(),
          model: 'user',
        });

        // Assistant generated image message
        const imgMarkdown = `![${prompt.trim()}](${result.imageUrl})\n\n*Image générée avec **${result.model}** (Format ${aspectRatio})*`;
        db.addMessage({
          id: `msg_${Date.now()}_a_img`,
          conversationId: conv.id,
          role: 'assistant',
          content: imgMarkdown,
          createdAt: new Date().toISOString(),
          model: result.model,
          imageUrl: result.imageUrl,
          imagePrompt: prompt.trim(),
        });
      }
    }

    return res.json({
      success: true,
      image: result,
    });
  } catch (err: any) {
    console.error('Image generation error:', err);
    return res.status(500).json({
      error: err.message || 'Échec de la génération de l\'image.',
    });
  }
});

app.post('/api/images/edit', authenticateToken, async (req: AuthenticatedRequest, res) => {
  const userId = req.user!.id;
  const { prompt, imageBase64, mimeType = 'image/png', aspectRatio = '1:1', conversationId } = req.body;

  if (!prompt || typeof prompt !== 'string' || !prompt.trim()) {
    return res.status(400).json({ error: 'Veuillez indiquer les instructions de modification.' });
  }
  if (!imageBase64 || typeof imageBase64 !== 'string') {
    return res.status(400).json({ error: 'Image de départ requise pour l\'édition.' });
  }

  const userSettings = db.getSettings(userId);

  try {
    const result = await aiEngine.editImage({
      prompt: prompt.trim(),
      imageBase64,
      mimeType,
      aspectRatio,
      customApiKey: userSettings?.customOpenAiKey,
    });

    // If conversationId provided, record messages in conversation
    if (conversationId) {
      const conv = db.getConversation(conversationId, userId);
      if (conv) {
        db.addMessage({
          id: `msg_${Date.now()}_u_edit`,
          conversationId: conv.id,
          role: 'user',
          content: `🖌️ Modifier l'image : "${prompt.trim()}"`,
          createdAt: new Date().toISOString(),
          model: 'user',
        });

        const imgMarkdown = `![${prompt.trim()}](${result.imageUrl})\n\n*Image modifiée avec **${result.model}***`;
        db.addMessage({
          id: `msg_${Date.now()}_a_edit`,
          conversationId: conv.id,
          role: 'assistant',
          content: imgMarkdown,
          createdAt: new Date().toISOString(),
          model: result.model,
          imageUrl: result.imageUrl,
          imagePrompt: prompt.trim(),
        });
      }
    }

    return res.json({
      success: true,
      image: result,
    });
  } catch (err: any) {
    console.error('Image edit error:', err);
    return res.status(500).json({
      error: err.message || 'Échec de la modification de l\'image.',
    });
  }
});

// --- Audio Transcription Route (utilisant gemini-3.5-transcribe) ---
app.post('/api/audio/transcribe', authenticateToken, async (req: AuthenticatedRequest, res) => {
  const userId = req.user!.id;
  const { audioBase64, mimeType = 'audio/webm' } = req.body;

  if (!audioBase64 || typeof audioBase64 !== 'string') {
    return res.status(400).json({ error: 'Fichier audio manquant ou invalide.' });
  }

  const userSettings = db.getSettings(userId);

  try {
    const text = await aiEngine.transcribeAudio({
      audioBase64,
      mimeType,
      customApiKey: userSettings?.customOpenAiKey,
    });

    return res.json({ text });
  } catch (err: any) {
    console.error('Erreur transcription audio gemini-3.5-transcribe:', err);
    return res.status(500).json({
      error: err.message || 'Échec de la transcription audio.',
    });
  }
});

// --- DeepMind Science Skills Routes (AlphaFold, PDB, PubChem, Europe PMC) ---
app.get('/api/science/protein/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const data = await scienceService.getProtein(id);
    return res.json(data);
  } catch (err: any) {
    return res.status(404).json({ error: err.message || 'Protéine introuvable.' });
  }
});

app.get('/api/science/chemical/:query', async (req, res) => {
  try {
    const { query } = req.params;
    const data = await scienceService.getChemical(query);
    return res.json(data);
  } catch (err: any) {
    return res.status(404).json({ error: err.message || 'Composé chimique introuvable.' });
  }
});

app.get('/api/science/literature/:query', async (req, res) => {
  try {
    const { query } = req.params;
    const data = await scienceService.getLiterature(query);
    return res.json({ results: data });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Erreur lors de la recherche bibliographique.' });
  }
});

// Helper to detect in-chat image generation requests (e.g. "une image d'un chat", "une image d'un schéma", "dessine un chat")
function extractImageGenerationPrompt(rawText: string | undefined): string | null {
  if (!rawText) return null;
  const text = rawText.trim();
  if (text.length < 2 || text.length > 500) return null;

  // Normalize accents and lowercasing for intent detection
  const normalized = text
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/['’]/g, "'")
    .trim();

  // Strip polite prefixes
  const cleanNorm = normalized
    .replace(/^(?:peux-tu|pourrais-tu|merci de|stp|s'il te plait|veuillez|est-ce que tu peux|tu peux)\s+/i, '')
    .trim();

  const stripFillers = (s: string) =>
    s.replace(/\s+(?:par exemple|stp|s'il te pla[iî]t|s'il vous pla[iî]t|merci)\s*$/i, '').trim();

  // 1. "genere/cree/fais/dessine/donne/produis/affiche [moi] [une] image [de/du/d'un/dun] ..."
  const m1 = cleanNorm.match(/^(?:genere(?:[- ]moi)?|cree(?:[- ]moi)?|fais(?:[- ]moi)?|dessine(?:[- ]moi)?|affiche(?:[- ]moi)?|produis(?:[- ]moi)?|donne(?:[- ]moi)?)\s+(?:une?\s+|l'|des?\s+)?image\s+(?:d'|de\s+|du\s+|d'un\s+|dun\s+|d'une\s+|dune\s+)?(.+)$/i);
  if (m1 && m1[1]) {
    const rawTarget = text.slice(cleanNorm.indexOf(m1[1])).trim();
    return stripFillers(rawTarget);
  }

  // 2. "[une/l'] image [d'/de/du/d'un/dun] ..."
  const m2 = cleanNorm.match(/^(?:une?|l')?\s*image\s+(?:d'|de\s+|du\s+|d'un\s+|dun\s+|d'une\s+|dune\s+)(.+)$/i);
  if (m2 && m2[1]) {
    const rawTarget = text.slice(cleanNorm.indexOf(m2[1])).trim();
    return stripFillers(rawTarget);
  }

  // 3. "dessine/illustre [moi] [un/une] ..."
  const m3 = cleanNorm.match(/^(?:dessine(?:[- ]moi)?|illustre(?:[- ]moi)?)\s+(?:un\s+|une\s+|des\s+|le\s+|la\s+|l')?(.+)$/i);
  if (m3 && m3[1]) {
    const rawTarget = text.slice(cleanNorm.indexOf(m3[1])).trim();
    return stripFillers(rawTarget);
  }

  // 4. "fais-moi un dessin/visuel/schema visuel de ..."
  const m4 = cleanNorm.match(/^(?:fais|cree|genere)(?:[- ]moi)?\s+(?:un\s+)?(?:dessin|visuel|illustration|schema\s+visuel)\s+(?:d'|de\s+|du\s+|d'un\s+|dun\s+|d'une\s+|dune\s+)?(.+)$/i);
  if (m4 && m4[1]) {
    const rawTarget = text.slice(cleanNorm.indexOf(m4[1])).trim();
    return stripFillers(rawTarget);
  }

  // 5. English patterns
  const m5 = cleanNorm.match(/^(?:generate|create|draw|make|show)\s+(?:me\s+)?(?:an?\s+)?(?:image|picture|drawing|illustration)\s+(?:of\s+)?(.+)$/i);
  if (m5 && m5[1]) {
    const rawTarget = text.slice(cleanNorm.indexOf(m5[1])).trim();
    return stripFillers(rawTarget);
  }

  const m6 = cleanNorm.match(/^(?:an?\s+)?(?:image|picture)\s+of\s+(.+)$/i);
  if (m6 && m6[1]) {
    const rawTarget = text.slice(cleanNorm.indexOf(m6[1])).trim();
    return stripFillers(rawTarget);
  }

  return null;
}

// --- Chat Streaming Route (SSE) ---
app.post('/api/chat/stream', authenticateToken, async (req: AuthenticatedRequest, res) => {
  const userId = req.user!.id;
  const { conversationId, message, mode, regenerate, groundingPreference, speedMode, latLng, attachment, attachments, clientTime } = req.body;

  let conv = db.getConversation(conversationId, userId);
  if (!conv) {
    // Auto-create conversation if none provided
    const newMode: RyxiaMode = ['general', 'code', 'study', 'creative', 'fast'].includes(mode) ? mode : 'general';
    conv = db.createConversation({
      id: conversationId || `conv_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      userId,
      title: message ? message.slice(0, 40) : (attachment?.name ? `Analyse: ${attachment.name.slice(0, 30)}` : 'Nouvelle conversation'),
      mode: newMode,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
  }

  // Update mode if explicitly provided
  if (mode && mode !== conv.mode && ['general', 'code', 'study', 'creative', 'fast'].includes(mode)) {
    conv = db.updateConversation(conv.id, userId, { mode })!;
  }

  // If regenerate, pop last assistant message
  if (regenerate) {
    db.deleteLastAssistantMessage(conv.id);
  } else if (message || attachment || (Array.isArray(attachments) && attachments.length > 0)) {
    // Process up to 4 attached images or documents
    const rawAttachments: any[] = Array.isArray(attachments) && attachments.length > 0
      ? attachments.slice(0, 4)
      : (attachment ? [attachment] : []);

    const processedAttachments = rawAttachments.map((att: any) => {
      const cleanBase64 = att.base64Data || (att.dataUrl ? att.dataUrl.split(',')[1] : undefined);
      const dataUrl = att.dataUrl || (cleanBase64 && (att.type?.startsWith('image/') || !att.type) ? `data:${att.type || 'image/jpeg'};base64,${cleanBase64}` : undefined);
      return {
        name: att.name || 'Fichier joint',
        type: att.type || 'image/jpeg',
        size: att.size || 0,
        dataUrl,
        base64Data: cleanBase64,
        textContent: att.textContent,
      };
    });

    const userMsg: Message = {
      id: `msg_${Date.now()}_u`,
      conversationId: conv.id,
      role: 'user',
      content: (message || '').trim(),
      createdAt: new Date().toISOString(),
      model: 'user',
      attachment: processedAttachments[0],
      attachments: processedAttachments.length > 0 ? processedAttachments : undefined,
    };
    db.addMessage(userMsg);

    // If this is the first message in conversation, update title dynamically
    const allMsgs = db.getMessages(conv.id, userId);
    if (allMsgs.length <= 1) {
      const msgText = (message || '').trim();
      const cleanTitle = msgText
        ? (msgText.slice(0, 48) + (msgText.length > 48 ? '...' : ''))
        : (processedAttachments[0]?.name ? `Images : ${processedAttachments.length} fichier(s)` : 'Nouvelle conversation');
      db.updateConversation(conv.id, userId, { title: cleanTitle });
    }
  }

  // Fetch full conversation history for context memory with multimodal attachment support
  const history = db.getMessages(conv.id, userId);
  const contextMessages = history.map(m => {
    const rawList = (m.attachments && m.attachments.length > 0)
      ? m.attachments
      : (m.attachment ? [m.attachment] : []);
    const chatAtts = rawList.map(a => ({
      name: a.name,
      mimeType: a.type,
      base64Data: a.base64Data,
      textContent: a.textContent,
    }));
    return {
      role: m.role as 'user' | 'assistant' | 'system',
      content: m.content,
      attachment: chatAtts[0],
      attachments: chatAtts,
    };
  });

  const userSettings = db.getSettings(userId);
  const effectiveSpeedMode = speedMode || userSettings.speedMode || (conv.mode === 'fast' ? 'turbo' : 'balanced');

  // Set SSE Headers with X-Accel-Buffering disabled for zero-latency streaming
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders?.();

  // Send initial conversation metadata
  res.write(`data: ${JSON.stringify({ type: 'init', conversationId: conv.id, title: conv.title, mode: conv.mode, speedMode: effectiveSpeedMode })}\n\n`);

  let accumulatedText = '';
  const abortController = new AbortController();

  res.on('close', () => {
    if (!res.writableEnded) {
      abortController.abort();
    }
  });

  try {
    // Check if user specifically requested an image generation in chat (e.g. "une image dun shema", "une image dun chat", etc.)
    const detectedImagePrompt = extractImageGenerationPrompt(message);
    const hasAttachments = Boolean(attachment || (Array.isArray(attachments) && attachments.length > 0));

    if (detectedImagePrompt && !hasAttachments && !regenerate) {
      res.write(`data: ${JSON.stringify({ type: 'chunk', text: '🎨 **Création visuelle en cours...**\n\n' })}\n\n`);
      (res as any).flush?.();

      try {
        let generationPrompt = detectedImagePrompt;
        if (/^sch?[eé]ma/i.test(detectedImagePrompt)) {
          generationPrompt = `Un schéma explicatif clair, précis et esthétique, infographie pédagogique détaillée avec annotations : ${detectedImagePrompt}`;
        } else {
          generationPrompt = `Une illustration ou photographie détaillée de haute qualité : ${detectedImagePrompt}`;
        }

        const imgResult = await aiEngine.generateImage({
          prompt: generationPrompt,
          aspectRatio: '1:1',
          customApiKey: userSettings.customOpenAiKey,
        });

        const assistantMsg: Message = {
          id: `msg_${Date.now()}_a`,
          conversationId: conv!.id,
          role: 'assistant',
          content: `Voici l'image générée pour votre demande : **${detectedImagePrompt}**`,
          imageUrl: imgResult.imageUrl,
          imagePrompt: detectedImagePrompt,
          createdAt: new Date().toISOString(),
          model: imgResult.model || 'RYXIA Vector Studio',
        };
        db.addMessage(assistantMsg);

        res.write(`data: ${JSON.stringify({ type: 'done', message: assistantMsg })}\n\n`);
        res.end();
        return;
      } catch (err: any) {
        console.warn('Direct chat image generation failed, falling back to chat streaming:', err.message || err);
        // Fallback to regular chat streaming below
      }
    }

    await aiEngine.streamChat(
      {
        mode: conv.mode,
        messages: contextMessages,
        customApiKey: userSettings.customOpenAiKey,
        customModel: userSettings.customOpenAiModel || process.env.OPENAI_MODEL,
        providerPreference: userSettings.aiProvider || 'auto',
        groundingPreference: groundingPreference || 'auto',
        speedMode: effectiveSpeedMode,
        responseLength: userSettings.responseLength || 'balanced',
        latLng,
        clientTime,
        signal: abortController.signal,
      },
      {
        onChunk: (chunk: string) => {
          accumulatedText += chunk;
          res.write(`data: ${JSON.stringify({ type: 'chunk', text: chunk })}\n\n`);
          (res as any).flush?.();
        },
        onDone: (fullText: string, modelName: string, sources?: any[]) => {
          const finalContent = fullText || accumulatedText;
          const assistantMsg: Message = {
            id: `msg_${Date.now()}_a`,
            conversationId: conv!.id,
            role: 'assistant',
            content: finalContent,
            createdAt: new Date().toISOString(),
            model: modelName,
            sources,
          };
          db.addMessage(assistantMsg);

          res.write(`data: ${JSON.stringify({ type: 'done', message: assistantMsg })}\n\n`);
          res.end();
        },
        onError: (err: any) => {
          console.error('Chat stream error:', err);
          res.write(`data: ${JSON.stringify({ type: 'error', error: err.message || 'Une erreur est survenue lors de la génération.' })}\n\n`);
          res.end();
        },
      }
    );
  } catch (err: any) {
    console.error('Unexpected streaming error:', err);
    res.write(`data: ${JSON.stringify({ type: 'error', error: 'RYXIA est temporairement indisponible. Réessayez dans quelques instants.' })}\n\n`);
    res.end();
  }
});

// --- Settings Routes ---
app.get('/api/settings', authenticateToken, (req: AuthenticatedRequest, res) => {
  const userId = req.user!.id;
  const settings = db.getSettings(userId);
  return res.json({ settings });
});

app.patch('/api/settings', authenticateToken, (req: AuthenticatedRequest, res) => {
  const userId = req.user!.id;
  const updated = db.updateSettings(userId, req.body);
  return res.json({ settings: updated });
});

// --- Stats Route ---
app.get('/api/stats', authenticateToken, (req: AuthenticatedRequest, res) => {
  const userId = req.user!.id;
  const stats = db.getUserStats(userId);
  return res.json({ stats });
});

// --- Vite Middleware (Dev) or Static Hosting (Prod) ---
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        host: '0.0.0.0',
        port: PORT,
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const httpServer = http.createServer(app);
  setupLiveWebSocket(httpServer);

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`[RYXIA Engine] Server is active at http://0.0.0.0:${PORT}`);
    console.log(`[RYXIA Engine] Live Voice WebSocket endpoint: ws://0.0.0.0:${PORT}/api/live`);
    console.log(`[RYXIA Engine] Signature: RYXIA — by Adan | Your AI. Your way.`);
  });
}

startServer().catch((err) => {
  console.error('Fatal error starting RYXIA server:', err);
});
