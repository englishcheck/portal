const questionsSource = [
    // --- TO BE (AM, IS, ARE) ---
    {
        question: "If I ______ harder, I would have passed the exam.",
        options: ["had studied", "study", "studied", "have studied"],
        answer: 0,
        explanation: "Pola Type 3: If + Past Perfect (had + V3). Jadi jawaban yang benar adalah 'had studied'."
    },
    {
        question: "She ______ come to the party if you had invited her.",
        options: ["will", "would", "would have", "had"],
        answer: 2,
        explanation: "Klausa utama (result clause) Type 3 membutuhkan 'would have' + V3. Di sini sudah ada 'come' (V3), jadi kurang 'would have'."
    },
    {
        question: "If we had left earlier, we ______ the train.",
        options: ["would catch", "would have caught", "caught", "will catch"],
        answer: 1,
        explanation: "Result clause harus menggunakan 'would have' + V3 (caught)."
    },
    {
        question: "If they ______ to him, they would have understood.",
        options: ["listened", "had listened", "listen", "have listened"],
        answer: 1,
        explanation: "Klausa 'If' memerlukan Past Perfect: 'had' + V3 ('listened')."
    },
    {
        question: "I would have bought the car if I ______ enough money.",
        options: ["have", "had", "had had", "have had"],
        answer: 2,
        explanation: "Ini menjebak. Kita butuh Past Perfect. 'Had' pertama adalah auxiliary, 'had' kedua adalah V3 dari 'have'. Jadi: 'had had'."
    },
    {
        question: "If it hadn't rained, we ______ to the park.",
        options: ["would have gone", "would go", "will go", "went"],
        answer: 0,
        explanation: "Struktur standar: 'would have' + V3 ('gone')."
    },
    {
        question: "You ______ if you had been more careful.",
        options: ["wouldn't fall", "won't fall", "wouldn't have fallen", "didn't fall"],
        answer: 2,
        explanation: "Kalimat negatif Type 3: 'would not have' + V3 ('fallen')."
    },
    {
        question: "If I ______ you were waiting, I would have hurried.",
        options: ["know", "knew", "had known", "have known"],
        answer: 2,
        explanation: "Pengandaian masa lalu. Butuh 'had' + V3 ('known')."
    },
    {
        question: "He would have visited us if he ______ time.",
        options: ["had had", "has", "had", "would have"],
        answer: 0,
        explanation: "Sama seperti soal no. 5. Past Perfect dari 'have' adalah 'had had'."
    },
    {
        question: "If she ______ the bus, she would have been late.",
        options: ["misses", "missed", "had missed", "has missed"],
        answer: 2,
        explanation: "Butuh Past Perfect: 'had' + V3 ('missed')."
    },
    {
        question: "What ______ if you had won the lottery?",
        options: ["would you do", "will you do", "would you have done", "did you do"],
        answer: 2,
        explanation: "Pertanyaan Type 3: 'What would you have done?'"
    },
    {
        question: "If I ______ hungry, I would have eaten something.",
        options: ["was", "were", "had been", "been"],
        answer: 2,
        explanation: "Past Perfect dari to be (was/were) adalah 'had been'."
    },
    {
        question: "They would have helped you if they ______ about the problem.",
        options: ["know", "knew", "had known", "have known"],
        answer: 2,
        explanation: "Klausa 'If' di belakang tetap pakai Past Perfect ('had known')."
    },
    {
        question: "If we ______ a map, we wouldn't have gotten lost.",
        options: ["had taken", "took", "take", "taken"],
        answer: 0,
        explanation: "Butuh 'had' + V3 ('taken')."
    },
    {
        question: "The team ______ the game if they had played better.",
        options: ["would win", "won", "would have won", "will win"],
        answer: 2,
        explanation: "Result clause masa lalu: 'would have won'."
    },

    // --- INTERMEDIATE LEVEL (16-40) ---
    // Fokus: 'Could/Might' have, bentuk negatif yang lebih kompleks, 'had been + V-ing' (continuous), dan konteks logika.

    {
        question: "If I hadn't eaten so much, I ______ sick.",
        options: ["wouldn't feel", "wouldn't have felt", "didn't feel", "won't feel"],
        answer: 1,
        explanation: "Faktanya saya makan banyak dan merasa sakit DULU. Jadi pakai 'wouldn't have felt'."
    },
    {
        question: "You ______ the train if you had arrived 5 minutes earlier.",
        options: ["could catch", "could have caught", "can catch", "caught"],
        answer: 1,
        explanation: "'Could have' bisa menggantikan 'would have' untuk menyatakan kemungkinan/kemampuan di masa lalu."
    },
    {
        question: "If she ______ to university, she might have found a better job.",
        options: ["goes", "went", "had gone", "has gone"],
        answer: 2,
        explanation: "Klausa 'If' tetap wajib Past Perfect ('had gone') meskipun result clause pakai 'might have'."
    },
    {
        question: "I ______ you if I had had your number.",
        options: ["would call", "would have called", "called", "had called"],
        answer: 1,
        explanation: "Struktur standar: 'would have called'."
    },
    {
        question: "If the weather ______ better, we could have gone to the beach.",
        options: ["was", "were", "had been", "is"],
        answer: 2,
        explanation: "Bentuk nominal sentence (non-verb). Past Perfect dari 'be' adalah 'had been'."
    },
    {
        question: "What ______ if the police hadn't arrived?",
        options: ["would happen", "happened", "would have happened", "will happen"],
        answer: 2,
        explanation: "Pertanyaan spekulasi masa lalu: 'would have happened'."
    },
    {
        question: "If you ______ me, I wouldn't have forgotten.",
        options: ["remind", "reminded", "had reminded", "have reminded"],
        answer: 2,
        explanation: "Butuh 'had' + V3 ('reminded')."
    },
    {
        question: "She wouldn't have met him if she ______ to that party.",
        options: ["didn't go", "hadn't gone", "hasn't gone", "wouldn't go"],
        answer: 1,
        explanation: "Negatif Past Perfect: 'had not' + V3 ('gone')."
    },
    {
        question: "If I ______ English in school, I would have traveled more.",
        options: ["studied", "had studied", "study", "studying"],
        answer: 1,
        explanation: "Penyesalan masa lalu. Gunakan 'had studied'."
    },
    {
        question: "We ______ the project on time if the computer hadn't crashed.",
        options: ["would finish", "finished", "would have finished", "had finished"],
        answer: 2,
        explanation: "Result clause: 'would have finished'."
    },
    {
        question: "If he ______ faster, he might have won the race.",
        options: ["ran", "runs", "had run", "running"],
        answer: 2,
        explanation: "V3 dari 'run' adalah 'run' (run-ran-run). Jadi: 'had run'."
    },
    {
        question: "They ______ angry if you had told them the truth.",
        options: ["wouldn't be", "won't be", "wouldn't have been", "weren't"],
        answer: 2,
        explanation: "Karena 'angry' adalah kata sifat, gunakan 'been' setelah 'wouldn't have'. Jadi 'wouldn't have been'."
    },
    {
        question: "If I ______ sleeping, I would have heard the phone.",
        options: ["wasn't", "haven't been", "hadn't been", "am not"],
        answer: 2,
        explanation: "Past Perfect Continuous ('had been sleeping') menekankan durasi aktivitas di masa lalu."
    },
    {
        question: "You could have stayed with us if you ______ to a hotel.",
        options: ["didn't go", "hadn't gone", "haven't gone", "wouldn't go"],
        answer: 1,
        explanation: "Negatif Past Perfect: 'hadn't gone'."
    },
    {
        question: "If the driver ______ careful, the accident wouldn't have happened.",
        options: ["was", "were", "had been", "is"],
        answer: 2,
        explanation: "Butuh 'had been' untuk kata sifat 'careful'."
    },
    {
        question: "I ______ the job if the salary had been higher.",
        options: ["would take", "took", "would have taken", "had taken"],
        answer: 2,
        explanation: "Keputusan masa lalu yang tidak terjadi. 'Would have taken'."
    },
    {
        question: "If you ______ the instructions, you wouldn't have broken it.",
        options: ["read", "reading", "had read", "have read"],
        answer: 2,
        explanation: "V3 dari 'read' dibaca 'red'. Tulisannya tetap 'read'. Past Perfect: 'had read'."
    },
    {
        question: "We ______ so much food if we had known you weren't coming.",
        options: ["wouldn't cook", "didn't cook", "wouldn't have cooked", "hadn't cooked"],
        answer: 2,
        explanation: "Tindakan yang sudah terlanjur dilakukan (memasak). 'Wouldn't have cooked'."
    },
    {
        question: "If I had known it was your birthday, I ______ you a present.",
        options: ["bought", "would buy", "would have bought", "will buy"],
        answer: 2,
        explanation: "Niat masa lalu yang tidak terlaksana. 'Would have bought'."
    },
    {
        question: "She ______ passed the test even if she had studied.",
        options: ["wouldn't have", "didn't", "wouldn't", "hadn't"],
        answer: 0,
        explanation: "Bentuk singkat (elliptical). Lengkapnya: 'wouldn't have passed'. Kita bisa menyingkatnya menjadi 'wouldn't have'."
    },
    {
        question: "If the alarm ______ off, we would have woken up.",
        options: ["went", "had went", "had gone", "was going"],
        answer: 2,
        explanation: "V3 dari 'go' adalah 'gone'. Past perfect: 'had gone'."
    },
    {
        question: "I would have lent you the money if you ______ me.",
        options: ["asked", "had asked", "ask", "asking"],
        answer: 1,
        explanation: "Syarat masa lalu: 'had asked'."
    },
    {
        question: "If I ______ my camera, I would have taken photos.",
        options: ["didn't forget", "hadn't forgotten", "forgot", "haven't forgotten"],
        answer: 1,
        explanation: "Negatif V3: 'forgotten'. Jadi 'hadn't forgotten'."
    },
    {
        question: "The plants ______ if you had watered them.",
        options: ["wouldn't die", "didn't die", "wouldn't have died", "hadn't died"],
        answer: 2,
        explanation: "Akibat di masa lalu: 'wouldn't have died'."
    },
    {
        question: "Could you ______ the work if you had had more time?",
        options: ["finish", "have finished", "finished", "had finished"],
        answer: 1,
        explanation: "Pertanyaan dengan modal 'could'. Polanya: Could + S + have + V3. Jadi 'have finished'."
    },

    // --- EXPERT LEVEL (41-50) ---
    // Fokus: Inversi (Had I known...), Passive Voice, dan struktur formal/sastra.

    {
        question: "______ known about the traffic, I would have taken a different route.",
        options: ["If I", "Had I", "Did I", "Were I"],
        answer: 1,
        explanation: "Inversi Type 3: Menghilangkan 'If' dan memindahkan 'Had' ke depan. 'Had I known' = 'If I had known'."
    },
    {
        question: "Had you followed the advice, you ______ in this trouble.",
        options: ["wouldn't be", "wouldn't have been", "weren't", "hadn't been"],
        answer: 1,
        explanation: "Kombinasi Inversi dan Result. Kamu SUDAH dalam masalah (masa lalu sampai sekarang/status). Tapi karena ini murni Type 3 context (masa lalu), 'wouldn't have been' paling aman."
    },
    {
        question: "The building ______ destroyed if the fire fighters had arrived later.",
        options: ["would be", "would have been", "had been", "was"],
        answer: 1,
        explanation: "Passive Voice Type 3: 'would have been' + V3 (destroyed)."
    },
    {
        question: "______ for his help, I would have failed the project.",
        options: ["If it hadn't been", "Had it not been", "If it wasn't", "Had it not"],
        answer: 1,
        explanation: "Inversi negatif dari 'If it hadn't been for...'. Bentuk formalnya adalah 'Had it not been for...'."
    },
    {
        question: "I would have been happier ______ I stayed at home.",
        options: ["if", "had", "have", "provided"],
        answer: 1,
        explanation: "Inversi di klausa kedua. '...had I stayed' sama dengan '...if I had stayed'."
    },
    {
        question: "If the contract ______ signed, we would have started yesterday.",
        options: ["was", "were", "had been", "is"],
        answer: 2,
        explanation: "Passive Voice Past Perfect: 'had been' + V3 (signed)."
    },
    {
        question: "______ seen the danger, he would have warned us.",
        options: ["If he", "Did he", "Had he", "Were he"],
        answer: 2,
        explanation: "Inversi: 'Had he seen...' (Seandainya dia melihat...)."
    },
    {
        question: "We would have been ______ by the storm if we hadn't found shelter.",
        options: ["catch", "caught", "catching", "catched"],
        answer: 1,
        explanation: "Passive Voice: 'would have been' + V3. V3 dari catch adalah 'caught'."
    },
    {
        question: "Had I realized the risk, I ______ participated.",
        options: ["would never have", "will never have", "would have never", "did never"],
        answer: 0,
        explanation: "Penempatan adverb 'never' yang paling natural adalah setelah 'would'. Jadi: 'would never have'."
    },
    {
        question: "But for your assistance, we ______ the deadline.",
        options: ["would miss", "would have missed", "missed", "had missed"],
        answer: 1,
        explanation: "'But for' artinya 'If it hadn't been for'. Ini mengindikasikan Conditional Type 3. Result clause: 'would have missed'."
    }
];