/**
 * Push notification strings keyed by language code then event key.
 * Supported languages: en, ja, es, de, fr
 *
 * Parameterised tokens:
 *   {name}     - actor's name
 *   {eventTitle} - event title
 *   {coverage} - boost coverage %
 *   {count}    - numeric count
 *   {s}        - plural suffix (pass "" or "s")
 */

module.exports = {
  en: {
    newMatch: {
      title: "It's a match!",
      body: "You and someone else have matched. Check it out.",
    },
    superFlirtReceived: {
      title: "Super Flirt!",
      body: "{name} sent you a Super Flirt. See who!",
    },
    superFlirtMatched: {
      title: "It's a match!",
      body: "Someone matched with your Super Flirt. Start chatting now.",
    },
    boostActivated: {
      title: "Priority Boost is live 🔥",
      body: "You're showing up first for everyone near you. Go get those matches.",
    },
    boostWarning: {
      title: "6 hours left on your Boost",
      body: "Make the most of it while you're hot.",
    },
    boostExpired: {
      title: "Your Priority Boost has ended",
      body: "You reached {coverage}% of active users nearby. {count} Boost{s} left this month.",
    },
    boostCreditsReset: {
      title: "Your 4 Priority Boosts are back",
      body: "First one's on us. Tap to activate.",
    },
    eventCheckin: {
      title: "Participant Checked In",
      body: "{name} has arrived at \"{eventTitle}\"",
    },
    eventRemoved: {
      title: "Removed from Event",
      body: "You have been removed from \"{eventTitle}\"",
    },
    chatMessage: {
      title: "{name}",
      body: "{message}",
    },
  },

  ja: {
    newMatch: {
      title: "マッチしました！",
      body: "誰かとマッチしました。確認してみよう。",
    },
    superFlirtReceived: {
      title: "スーパーフラート！",
      body: "{name}さんがスーパーフラートを送りました。確認してみよう！",
    },
    superFlirtMatched: {
      title: "マッチしました！",
      body: "あなたのスーパーフラートにマッチしました。チャットを始めましょう。",
    },
    boostActivated: {
      title: "プライオリティブースト開始 🔥",
      body: "あなたのプロフィールが近くの全員に優先表示されています。",
    },
    boostWarning: {
      title: "ブースト残り6時間",
      body: "今が一番目立つとき。フル活用しよう。",
    },
    boostExpired: {
      title: "プライオリティブースト終了",
      body: "近くのアクティブユーザーの{coverage}%に表示されました。今月あと{count}回使えます。",
    },
    boostCreditsReset: {
      title: "ブーストが4回分リセットされました",
      body: "最初の1回は今すぐ使えます。タップして有効化しよう。",
    },
    eventCheckin: {
      title: "参加者がチェックインしました",
      body: "{name}さんが「{eventTitle}」に到着しました",
    },
    eventRemoved: {
      title: "イベントから削除されました",
      body: "「{eventTitle}」から削除されました",
    },
    chatMessage: {
      title: "{name}",
      body: "{message}",
    },
  },

  es: {
    newMatch: {
      title: "¡Tienes un match!",
      body: "Tú y otra persona se han gustado. Échale un vistazo.",
    },
    superFlirtReceived: {
      title: "¡Super Flirt!",
      body: "{name} te envió un Super Flirt. ¡Mira quién es!",
    },
    superFlirtMatched: {
      title: "¡Es un match!",
      body: "Alguien respondió a tu Super Flirt. Empieza a chatear.",
    },
    boostActivated: {
      title: "Priority Boost activo 🔥",
      body: "Apareces primero para todos los que están cerca. Ve por esos matches.",
    },
    boostWarning: {
      title: "6 horas restantes en tu Boost",
      body: "Sácale el máximo partido mientras estás en racha.",
    },
    boostExpired: {
      title: "Tu Priority Boost ha terminado",
      body: "Llegaste al {coverage}% de usuarios activos cercanos. Te quedan {count} Boost{s} este mes.",
    },
    boostCreditsReset: {
      title: "Tus 4 Priority Boosts han vuelto",
      body: "El primero es cortesía nuestra. Toca para activar.",
    },
    eventCheckin: {
      title: "Participante registrado",
      body: "{name} ha llegado a \"{eventTitle}\"",
    },
    eventRemoved: {
      title: "Eliminado del evento",
      body: "Has sido eliminado de \"{eventTitle}\"",
    },
    chatMessage: {
      title: "{name}",
      body: "{message}",
    },
  },

  de: {
    newMatch: {
      title: "Ein neues Match!",
      body: "Du und jemand anderes haben sich gegenseitig gemocht. Schau mal rein.",
    },
    superFlirtReceived: {
      title: "Super Flirt!",
      body: "{name} hat dir einen Super Flirt geschickt. Schau mal!",
    },
    superFlirtMatched: {
      title: "Es ist ein Match!",
      body: "Jemand hat deinen Super Flirt erwidert. Fang jetzt an zu chatten.",
    },
    boostActivated: {
      title: "Priority Boost ist live 🔥",
      body: "Dein Profil wird allen in der Nähe zuerst angezeigt.",
    },
    boostWarning: {
      title: "Noch 6 Stunden für deinen Boost",
      body: "Nutze ihn, solange du im Rampenlicht stehst.",
    },
    boostExpired: {
      title: "Dein Priority Boost ist beendet",
      body: "Du hast {coverage}% der aktiven Nutzer in der Nähe erreicht. Noch {count} Boost{s} diesen Monat.",
    },
    boostCreditsReset: {
      title: "Deine 4 Priority Boosts sind zurück",
      body: "Den ersten spendieren wir. Tippe zum Aktivieren.",
    },
    eventCheckin: {
      title: "Teilnehmer eingecheckt",
      body: "{name} ist bei \"{eventTitle}\" angekommen",
    },
    eventRemoved: {
      title: "Vom Event entfernt",
      body: "Du wurdest von \"{eventTitle}\" entfernt",
    },
    chatMessage: {
      title: "{name}",
      body: "{message}",
    },
  },

  fr: {
    newMatch: {
      title: "C'est un match !",
      body: "Toi et quelqu'un d'autre vous êtes plu. Allez voir.",
    },
    superFlirtReceived: {
      title: "Super Flirt !",
      body: "{name} t'a envoyé un Super Flirt. Découvre qui !",
    },
    superFlirtMatched: {
      title: "C'est un match !",
      body: "Quelqu'un a répondu à ton Super Flirt. Lance la conversation.",
    },
    boostActivated: {
      title: "Priority Boost en cours 🔥",
      body: "Tu apparais en premier pour tout le monde près de toi.",
    },
    boostWarning: {
      title: "Plus que 6 heures sur ton Boost",
      body: "Profites-en pendant que tu es en vedette.",
    },
    boostExpired: {
      title: "Ton Priority Boost est terminé",
      body: "Tu as atteint {coverage}% des utilisateurs actifs à proximité. Il te reste {count} Boost{s} ce mois-ci.",
    },
    boostCreditsReset: {
      title: "Tes 4 Priority Boosts sont de retour",
      body: "Le premier est offert. Appuie pour activer.",
    },
    eventCheckin: {
      title: "Participant enregistré",
      body: "{name} est arrivé à \"{eventTitle}\"",
    },
    eventRemoved: {
      title: "Retiré de l'événement",
      body: "Tu as été retiré de \"{eventTitle}\"",
    },
    chatMessage: {
      title: "{name}",
      body: "{message}",
    },
  },
};
