const questionsSource = [
    // --- TO BE (AM, IS, ARE) ---
    {
        question: "If I ______ a million dollars, I would buy a big house.",
        options: ["have", "had", "has", "having"],
        answer: 1,
        explanation: "Pola Type 2: If + Simple Past (V2). Bentuk lampau dari 'have' adalah 'had'."
    },
    {
        question: "If she ______ harder, she would pass the exam.",
        options: ["studied", "studies", "study", "studying"],
        answer: 0,
        explanation: "Kita membutuhkan Verb 2 (Past Tense) di dalam klausa 'If'. 'Studied' adalah bentuk lampau yang benar."
    },
    {
        question: "If I ______ you, I would apologize to him.",
        options: ["was", "am", "were", "be"],
        answer: 2,
        explanation: "Dalam pengandaian (conditional), kita menggunakan 'were' untuk semua subjek (termasuk I, He, She, It) untuk menunjukkan situasi imajiner."
    },
    {
        question: "He ______ help you if he had time.",
        options: ["will", "would", "can", "shall"],
        answer: 1,
        explanation: "Klausa utama (result clause) dalam Type 2 menggunakan 'would' + Verb 1."
    },
    {
        question: "What would you do if you ______ a ghost?",
        options: ["see", "saw", "seen", "seeing"],
        answer: 1,
        explanation: "Klausa 'If' harus menggunakan Simple Past. Bentuk V2 dari 'see' adalah 'saw'."
    },
    {
        question: "If we lived in Japan, we ______ speak Japanese.",
        options: ["will", "would", "can", "may"],
        answer: 1,
        explanation: "Situasi tidak nyata (kita tidak tinggal di Jepang). Maka result clause menggunakan 'would'."
    },
    {
        question: "If I ______ the answer, I would tell you.",
        options: ["know", "knew", "known", "knowing"],
        answer: 1,
        explanation: "Butuh V2 dari 'know', yaitu 'knew'. Artinya: 'Jika saya tahu (faktanya saya tidak tahu)'."
    },
    {
        question: "They would be happy if they ______ the lottery.",
        options: ["win", "won", "winning", "wins"],
        answer: 1,
        explanation: "Klausa 'If' di belakang tetap menggunakan aturan Simple Past. V2 dari 'win' adalah 'won'."
    },
    {
        question: "If it ______ today, we would cancel the picnic.",
        options: ["rain", "rained", "rains", "raining"],
        answer: 1,
        explanation: "Pengandaian tentang cuaca saat ini (faktanya tidak hujan). Gunakan V2 'rained'."
    },
    {
        question: "You ______ better if you exercised more.",
        options: ["feel", "felt", "would feel", "will feel"],
        answer: 2,
        explanation: "Klausa 'If' sudah pakai 'exercised' (V2), maka klausa utama butuh 'would' + V1 ('would feel')."
    },
    {
        question: "If I ______ a bird, I would fly to you.",
        options: ["was", "is", "were", "am"],
        answer: 2,
        explanation: "Aturan 'subjunctive': gunakan 'were' untuk semua subjek dalam pengandaian khayalan."
    },
    {
        question: "If he ______ his number, I would call him.",
        options: ["give", "given", "gave", "gives"],
        answer: 2,
        explanation: "Butuh V2 dari 'give', yaitu 'gave'."
    },
    {
        question: "She wouldn't work there if she ______ the boss.",
        options: ["doesn't like", "didn't like", "don't like", "won't like"],
        answer: 1,
        explanation: "Bentuk negatif Simple Past menggunakan 'did not' (didn't) + V1."
    },
    {
        question: "If I had a car, I ______ you to work.",
        options: ["drive", "drove", "would drive", "will drive"],
        answer: 2,
        explanation: "Result clause membutuhkan 'would' + basic verb 'drive'."
    },
    {
        question: "Where ______ you go if you could travel anywhere?",
        options: ["will", "did", "would", "do"],
        answer: 2,
        explanation: "Pertanyaan hipotetis menggunakan 'would' sebelum subjek."
    },

    // --- INTERMEDIATE LEVEL (16-40) ---
    // Fokus: Kalimat negatif, "Could" vs "Would", variasi posisi, dan konteks yang lebih spesifik.

    {
        question: "If I ______ busy, I would come to your party.",
        options: ["wasn't", "weren't", "am not", "wouldn't be"],
        answer: 1,
        explanation: "Bentuk negatif dari 'were' adalah 'were not' atau 'weren't'. Ini lebih tepat secara gramatikal daripada 'wasn't' untuk Type 2."
    },
    {
        question: "If you ______ to bed earlier, you wouldn't be tired.",
        options: ["go", "went", "gone", "going"],
        answer: 1,
        explanation: "Faktanya kamu bergadang. Pengandaiannya menggunakan V2 'went'."
    },
    {
        question: "I ______ that if I were you.",
        options: ["won't do", "wouldn't do", "didn't do", "don't do"],
        answer: 1,
        explanation: "Result clause negatif: 'would not' + V1 ('wouldn't do')."
    },
    {
        question: "If we ______ a map, we wouldn't be lost.",
        options: ["have", "had", "has", "having"],
        answer: 1,
        explanation: "Faktanya kita tidak punya peta. Gunakan V2 'had'."
    },
    {
        question: "Could you help me if you ______ busy?",
        options: ["weren't", "wasn't", "aren't", "won't be"],
        answer: 0,
        explanation: "Pertanyaan sopan dengan pengandaian. Gunakan 'weren't' untuk subjek 'you'."
    },
    {
        question: "If he ______ the truth, he wouldn't lie.",
        options: ["know", "knew", "known", "knows"],
        answer: 1,
        explanation: "Gunakan V2 'knew' untuk situasi hipotesis."
    },
    {
        question: "If I could sing, I ______ join the band.",
        options: ["will", "would", "can", "shall"],
        answer: 1,
        explanation: "'Could' di klausa If adalah bentuk lampau dari 'can'. Pasangannya di result clause adalah 'would'."
    },
    {
        question: "If it ______ for your help, I would fail.",
        options: ["weren't", "wasn't", "isn't", "aren't"],
        answer: 0,
        explanation: "Frasa tetap: 'If it weren't for...' artinya 'Jika bukan karena...'."
    },
    {
        question: "They ______ angry if they knew the truth.",
        options: ["would be", "will be", "are", "were"],
        answer: 0,
        explanation: "Result clause membutuhkan 'would' + verb. Karena 'angry' adalah kata sifat, gunakan 'be' sebagai verb penghubung."
    },
    {
        question: "Who ______ you choose if you could vote?",
        options: ["will", "would", "did", "do"],
        answer: 1,
        explanation: "Pertanyaan pengandaian (imaginary situation) menggunakan 'would'."
    },
    {
        question: "If the internet didn't work, what ______ you do?",
        options: ["will", "can", "would", "did"],
        answer: 2,
        explanation: "Pertanyaan lanjutan untuk situasi hipotesis. Gunakan 'would'."
    },
    {
        question: "I would buy a yacht if I ______ rich.",
        options: ["am", "was", "were", "be"],
        answer: 2,
        explanation: "Penggunaan 'were' untuk subjek 'I' dalam Conditional Type 2 adalah standar baku grammar."
    },
    {
        question: "If she ______ French, she could move to Paris.",
        options: ["speak", "speaks", "spoke", "spoken"],
        answer: 2,
        explanation: "V2 dari 'speak' adalah 'spoke'. Di result clause, 'could' bisa menggantikan 'would' untuk menyatakan kemampuan (ability)."
    },
    {
        question: "My parents ______ worry if I didn't call them.",
        options: ["will", "would", "did", "do"],
        answer: 1,
        explanation: "Prediksi situasi hipotesis: 'would worry'."
    },
    {
        question: "If you ______ the President, what would you change?",
        options: ["are", "was", "were", "be"],
        answer: 2,
        explanation: "Situasi khayalan murni (tidak mungkin terjadi). Wajib pakai 'were'."
    },
    {
        question: "The world ______ a better place if there were no wars.",
        options: ["will be", "would be", "is", "was"],
        answer: 1,
        explanation: "Result clause hipotesis masa depan/sekarang menggunakan 'would be'."
    },
    {
        question: "If I didn't have to work, I ______ on the beach right now.",
        options: ["would lie", "would be lying", "lied", "lying"],
        answer: 1,
        explanation: "Ini adalah variasi 'Continuous'. Kita bisa pakai 'would be + V-ing' untuk menekankan aktivitas yang sedang berlangsung dalam khayalan."
    },
    {
        question: "It would be nice if you ______ so much noise.",
        options: ["don't make", "won't make", "didn't make", "not make"],
        answer: 2,
        explanation: "Harapan sopan atau keluhan. Klausa 'If' negatif past tense: 'didn't make'."
    },
    {
        question: "If I ______ where he lived, I would visit him.",
        options: ["find", "found", "finds", "finding"],
        answer: 1,
        explanation: "V2 dari 'find' adalah 'found'."
    },
    {
        question: "You ______ weight if you stopped eating junk food.",
        options: ["lose", "lost", "would lose", "will lose"],
        answer: 2,
        explanation: "Result clause: 'would' + V1 ('lose')."
    },
    {
        question: "If I had a camera, I ______ take a picture.",
        options: ["can", "will", "could", "shall"],
        answer: 2,
        explanation: "Di sini 'could' lebih tepat daripada 'would' karena menekankan pada kemampuan (ability) untuk mengambil foto."
    },
    {
        question: "He wouldn't be late if he ______ up earlier.",
        options: ["get", "got", "gotten", "getting"],
        answer: 1,
        explanation: "Klausa 'If' di belakang. V2 dari 'get' adalah 'got'."
    },
    {
        question: "If animals ______ talk, what would they say?",
        options: ["can", "could", "will", "would"],
        answer: 1,
        explanation: "Bentuk lampau dari 'can' adalah 'could'. 'If animals could talk' (Jika hewan bisa bicara)."
    },
    {
        question: "I ______ lend you the money if I had it.",
        options: ["will", "would", "can", "may"],
        answer: 1,
        explanation: "Struktur standar: Result (Would) + If (Past)."
    },
    {
        question: "If you ______ a wallet on the street, what would you do?",
        options: ["find", "found", "finds", "finding"],
        answer: 1,
        explanation: "Situasi hipotesis (V2 found)."
    },

    // --- EXPERT LEVEL (41-50) ---
    // Fokus: Inversi (Were I...), Struktur formal, Passive Voice, dan nuansa makna yang kompleks.

    {
        question: "______ I richer, I would buy that company.",
        options: ["If", "Were", "Was", "Had"],
        answer: 1,
        explanation: "Ini adalah bentuk Inversi (pembalikan) dari 'If I were richer'. Kita menghilangkan 'If' dan memindahkan 'Were' ke depan."
    },
    {
        question: "If the decision ______ mine to make, I would cancel the project.",
        options: ["is", "was", "were", "be"],
        answer: 2,
        explanation: "Subjek 'decision' adalah tunggal, tapi dalam konteks formal/subjunctive type 2, 'were' adalah pilihan yang paling tepat secara akademis."
    },
    {
        question: "______ you to accept the job, you would have to move to London.",
        options: ["If", "Did", "Were", "Had"],
        answer: 2,
        explanation: "Inversi tipe lanjut: 'If you were to accept' menjadi 'Were you to accept'. Menunjukkan kemungkinan yang sangat kecil atau formalitas."
    },
    {
        question: "If I ______ in your shoes, I would resign.",
        options: ["am", "was", "were", "have been"],
        answer: 2,
        explanation: "Idiom 'In your shoes' (di posisimu). Gunakan 'were' untuk grammar yang sempurna."
    },
    {
        question: "If taxes ______ lowered, the economy might improve.",
        options: ["are", "were", "was", "had been"],
        answer: 1,
        explanation: "Passive Voice dalam Conditional Type 2. 'Were lowered' (jika pajak diturunkan). Gunakan 'were' karena 'taxes' jamak dan ini situasi hipotesis."
    },
    {
        question: "I would be grateful if you ______ me the details.",
        options: ["send", "sent", "sending", "would send"],
        answer: 1,
        explanation: "Permintaan sangat sopan. Gunakan V2 'sent' setelah 'if'."
    },
    {
        question: "______ he to arrive now, he would miss the beginning.",
        options: ["If", "Was", "Were", "Did"],
        answer: 2,
        explanation: "Inversi dari 'If he were to arrive'. Struktur ini (Were + S + to infinitive) digunakan untuk hipotesis masa depan yang kurang mungkin terjadi."
    },
    {
        question: "If it ______ for the heavy rain, we would be hiking now.",
        options: ["isn't", "weren't", "wasn't", "not"],
        answer: 1,
        explanation: "Frasa 'If it weren't for...' (Jika bukan karena...). Selalu gunakan 'weren't' dalam bentuk ini."
    },
    {
        question: "Unless she ______ apologize, I wouldn't forgive her.",
        options: ["did", "does", "were", "had"],
        answer: 0,
        explanation: "Dalam Type 2, 'Unless' diikuti oleh Past Tense. Kita bisa menggunakan auxiliary 'did' untuk penekanan (emphatic do) atau jika verb-nya membutuhkan."
    },
    {
        question: "If I had the authority, the rules ______ changed immediately.",
        options: ["would be", "will be", "would have been", "are"],
        answer: 0,
        explanation: "Result clause bentuk Passive: 'would be' + V3 (changed). Artinya 'aturan akan diubah'."
    }
];