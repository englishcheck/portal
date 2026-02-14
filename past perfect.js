const questionsSource = [
    // --- LEVEL: BEGINNER (15 Soal) ---
    // Fokus: Struktur dasar (Had + V3) dan pemahaman urutan kejadian sederhana.

    {
        question: "I ______ the email before I realized it was sent to the wrong person.",
        options: ["have sent", "had sent", "send", "was sending"],
        answer: 1,
        explanation: "Kejadian 'mengirim email' terjadi SEBELUM kejadian 'menyadari' (realized). Karena 'realized' adalah masa lampau (Past Tense), maka kejadian sebelumnya harus Past Perfect (had sent)."
    },
    {
        question: "She ______ never ______ an elephant before she went to the zoo.",
        options: ["had / see", "has / seen", "had / seen", "was / seeing"],
        answer: 2,
        explanation: "Struktur Past Perfect adalah 'had + Verb 3 (Past Participle)'. Verb 3 dari 'see' adalah 'seen'. Jadi jawabannya 'had / seen'."
    },
    {
        question: "The train ______ by the time we arrived at the station.",
        options: ["left", "had left", "has left", "leaves"],
        answer: 1,
        explanation: "Kereta berangkat DULUAN sebelum kita tiba. Aksi pertama di masa lampau menggunakan Past Perfect: 'had left'."
    },
    {
        question: "We were not hungry because we ______ lunch.",
        options: ["had already eaten", "have already eaten", "ate", "eat"],
        answer: 0,
        explanation: "Alasan tidak lapar (were not hungry - Past) adalah karena sudah makan sebelumnya. Gunakan 'had already eaten'."
    },
    {
        question: "______ they ______ the work when the boss came?",
        options: ["Have / finished", "Did / finish", "Had / finished", "Was / finishing"],
        answer: 2,
        explanation: "Untuk pertanyaan Past Perfect, gunakan auxiliary 'Had' di depan subjek, diikuti V3. 'Had they finished...?'"
    },
    {
        question: "I lost the key that he ______ to me.",
        options: ["gave", "has given", "had given", "giving"],
        answer: 2,
        explanation: "Dia memberikan kunci (aksi 1), lalu saya menghilangkannya (aksi 2). Aksi 1 harus Past Perfect: 'had given'."
    },
    {
        question: "She told me that she ______ to Paris in 2010.",
        options: ["has been", "had been", "is", "was"],
        answer: 1,
        explanation: "Dalam kalimat tidak langsung (Reported Speech) dengan main clause masa lampau (told), bentuk lampau mundur menjadi Past Perfect. 'Had been' adalah bentuk yang tepat."
    },
    {
        question: "Before he went to sleep, he ______ his homework.",
        options: ["finished", "has finished", "had finished", "finishes"],
        answer: 2,
        explanation: "Ada kata 'Before'. Aksi menyelesaikan PR terjadi sebelum tidur. Maka: 'had finished'."
    },
    {
        question: "The plants died because I ______ to water them.",
        options: ["forgot", "have forgotten", "had forgotten", "forget"],
        answer: 2,
        explanation: "Tanaman mati (died - Past) karena kelalaian sebelumnya. Penyebab di masa lampau yang lebih awal menggunakan 'had forgotten'."
    },
    {
        question: "When I turned on the radio, the news ______.",
        options: ["finished", "had already finished", "has finished", "finishes"],
        answer: 1,
        explanation: "Berita sudah selesai SAAT radio dinyalakan. Kejadian selesai duluan = Past Perfect."
    },
    {
        question: "______ you ever ______ sushi before you moved to Japan?",
        options: ["Had / ate", "Had / eaten", "Have / eaten", "Did / eat"],
        answer: 1,
        explanation: "Pola pertanyaan Past Perfect: Had + S + V3. V3 dari eat adalah 'eaten'."
    },
    {
        question: "He felt nervous because he ______ on a plane before.",
        options: ["had never flown", "never flies", "has never flown", "did not fly"],
        answer: 0,
        explanation: "Perasaan gugup terjadi di masa lalu (felt), penyebabnya adalah pengalaman (belum pernah terbang) sebelum momen itu."
    },
    {
        question: "After they ______ the bill, they left the restaurant.",
        options: ["paid", "have paid", "had paid", "pay"],
        answer: 2,
        explanation: "Urutannya: Bayar dulu (Action 1), baru pergi (Action 2). Action 1 pakai Past Perfect: 'had paid'."
    },
    {
        question: "My phone didn't work because I ______ to charge it.",
        options: ["forgot", "have forgotten", "had forgotten", "forgetting"],
        answer: 2,
        explanation: "Penyebab hp mati adalah lupa mencharge sebelumnya. 'Had forgotten' adalah bentuk yang paling tepat untuk kausalitas di masa lampau."
    },
    {
        question: "By the age of 20, she ______ three novels.",
        options: ["wrote", "has written", "had written", "writes"],
        answer: 2,
        explanation: "Frasa 'By + [waktu lampau]' adalah sinyal kuat untuk Past Perfect. Menunjukkan pencapaian sebelum titik waktu tertentu di masa lalu."
    },

    // --- LEVEL: INTERMEDIATE (15 Soal) ---
    // Fokus: Time signals kompleks (By the time, As soon as), perbandingan tenses, dan logika cerita.

    {
        question: "By the time the firefighters arrived, the building ______ down.",
        options: ["burned", "has burned", "had burned", "burns"],
        answer: 2,
        explanation: "'By the time' artinya 'menjelang/pada saat'. Jika diikuti Past Tense (arrived), maka aksi pasangannya harus Past Perfect (had burned) karena sudah terjadi sebelumnya."
    },
    {
        question: "She didn't want to go to the cinema because she ______ the film twice.",
        options: ["saw", "has seen", "had seen", "was seeing"],
        answer: 2,
        explanation: "Simple Past (saw) kurang tepat karena ada penekanan 'pengalaman yang sudah selesai' sebelum dia menolak. Past Perfect (had seen) menekankan efek dari pengalaman tersebut."
    },
    {
        question: "The house was quiet when I got home. Everybody ______ to bed.",
        options: ["went", "has gone", "had gone", "goes"],
        answer: 2,
        explanation: "Saat sampai di rumah, orang-orang SUDAH tidak ada (di tempat tidur). Aksi 'pergi tidur' terjadi sebelum 'sampai di rumah'."
    },
    {
        question: "No sooner ______ the door than the phone rang.",
        options: ["I had opened", "had I opened", "did I open", "I opened"],
        answer: 1,
        explanation: "Ini adalah bentuk inversi dengan 'No sooner'. Polanya: 'No sooner + had + Subject + V3'. Jadi jawabannya 'had I opened'."
    },
    {
        question: "I couldn't believe that he ______ my birthday.",
        options: ["forgot", "has forgotten", "had forgotten", "forgets"],
        answer: 2,
        explanation: "Rasa tidak percaya (couldn't believe) terjadi karena kejadian melupakan itu sudah terjadi sebelumnya."
    },
    {
        question: "The teacher asked if we ______ for the exam.",
        options: ["studied", "have studied", "had studied", "study"],
        answer: 2,
        explanation: "Reported Speech. Kalimat langsungnya mungkin: 'Have you studied?'. Dalam bentuk lampau (asked), 'Have' berubah menjadi 'Had'."
    },
    {
        question: "He ______ his leg, so he couldn't play in the final match.",
        options: ["broke", "has broken", "had broken", "breaks"],
        answer: 2,
        explanation: "Penyebab (kaki patah) terjadi sebelum akibat (tidak bisa main). Menggunakan Past Perfect memperjelas urutan sebab-akibat di masa lampau."
    },
    {
        question: "It was the first time I ______ such a beautiful sunset.",
        options: ["saw", "have seen", "had seen", "see"],
        answer: 2,
        explanation: "Pola 'It WAS the first time...' selalu diikuti Past Perfect (had seen). Jika 'It IS the first time...', diikuti Present Perfect."
    },
    {
        question: "She realized she ______ her wallet on the bus only after she got off.",
        options: ["left", "has left", "had left", "leaves"],
        answer: 2,
        explanation: "Menyadari (realized) terjadi setelah turun. Meninggalkan dompet (left) terjadi JAUH sebelumnya (saat masih di bus). Maka: 'had left'."
    },
    {
        question: "Until yesterday, I ______ never ______ the truth about the accident.",
        options: ["have / known", "had / known", "did / know", "was / knowing"],
        answer: 1,
        explanation: "Kata 'Until yesterday' (sampai kemarin) membatasi durasi ketidaktahuan di masa lampau. Gunakan Past Perfect 'had known'."
    },
    {
        question: "The road was blocked because a tree ______ during the storm.",
        options: ["fell", "has fallen", "had fallen", "falls"],
        answer: 2,
        explanation: "Pohon jatuh (had fallen) terjadi lebih dulu daripada jalanan ditutup (was blocked)."
    },
    {
        question: "Hardly ______ the station when the train arrived.",
        options: ["we had reached", "did we reach", "had we reached", "we reached"],
        answer: 2,
        explanation: "Sama seperti 'No sooner', kata 'Hardly' di awal kalimat memicu inversi: 'Hardly + had + S + V3'."
    },
    {
        question: "Before 2015, they ______ in five different countries.",
        options: ["lived", "have lived", "had lived", "live"],
        answer: 2,
        explanation: "Penanda waktu 'Before + tahun lampau' mengindikasikan Past Perfect untuk menyatakan pengalaman sebelum tahun tersebut."
    },
    {
        question: "When the police arrived, the evidence ______.",
        options: ["destroyed", "had been destroyed", "was destroying", "has destroyed"],
        answer: 1,
        explanation: "Bentuk Passive Voice dari Past Perfect: 'had + been + V3'. Bukti itu SUDAH dihancurkan (pasif) sebelum polisi datang."
    },
    {
        question: "I ______ to send the parcel, but I forgot.",
        options: ["meant", "had meant", "have meant", "mean"],
        answer: 1,
        explanation: "Menggunakan 'had meant' (tadinya bermaksud) menunjukkan niat di masa lalu yang tidak terlaksana sebelum kejadian lain (lupa)."
    },

    // --- LEVEL: EXPERT (15 Soal) ---
    // Fokus: Third Conditional (If clauses), Inversi tingkat lanjut, dan nuansa makna yang dalam.

    {
        question: "If I ______ known you were in town, I would have invited you to dinner.",
        options: ["have", "had", "would have", "was"],
        answer: 1,
        explanation: "Ini adalah Third Conditional (Pengandaian tipe 3). Rumusnya: 'If + S + Past Perfect (had + V3), S + would have + V3'. Jawabannya 'had'."
    },
    {
        question: "He wondered if he ______ a mistake by resigning.",
        options: ["made", "has made", "had made", "makes"],
        answer: 2,
        explanation: "Subtle Reporting. Dia bertanya-tanya tentang aksi yang sudah SELESAI dilakukan sebelumnya (resigning). 'Had made' adalah bentuk paling akurat secara gramatikal."
    },
    {
        question: "I wish I ______ harder for the exam. Now I regret it.",
        options: ["studied", "have studied", "had studied", "would study"],
        answer: 2,
        explanation: "Pola 'I wish' untuk penyesalan di masa lampau (regret) menggunakan Past Perfect. 'I wish I had studied' (Saya berharap dulu saya belajar - faktanya tidak)."
    },
    {
        question: "The suspect claimed he ______ at home all night, but witnesses saw him out.",
        options: ["was", "has been", "had been", "is"],
        answer: 2,
        explanation: "Klaim tersangka mengenai posisinya di masa lampau, sebelum dia diperiksa polisi. Reported speech dari 'I was at home' atau 'I have been at home' menjadi 'he had been'."
    },
    {
        question: "Scarcely ______ entered the room when the lights went out.",
        options: ["she had", "had she", "did she", "has she"],
        answer: 1,
        explanation: "Inversi dengan 'Scarcely'. Polanya identik dengan Hardly/No sooner: Aux 'had' mendahului subjek. 'Had she entered'."
    },
    {
        question: "If she ______ the bus, she wouldn't have been late for the interview.",
        options: ["hadn't missed", "hasn't missed", "didn't miss", "wouldn't miss"],
        answer: 0,
        explanation: "Third Conditional negatif. Fakta masa lalu: She missed the bus (Dia ketinggalan). Pengandaian: If she HADN'T missed."
    },
    {
        question: "He acted as if he ______ the boss, giving orders to everyone.",
        options: ["is", "was", "has been", "had been"],
        answer: 3,
        explanation: "Pola 'as if' (seolah-olah) untuk situasi yang tidak nyata di masa lampau (counter-factual) menggunakan Past Perfect. Dia bukan bos, tapi bertindak seolah-olah dia 'had been' bos."
    },
    {
        question: "The ancient ruins looked as though they ______ untouched for centuries.",
        options: ["remained", "have remained", "had remained", "remain"],
        answer: 2,
        explanation: "Observasi di masa lampau (looked) tentang kondisi yang sudah berlangsung lama sebelumnya (untouched for centuries). Gunakan 'had remained'."
    },
    {
        question: "By the time the project is finished, we ______ on it for two years. (Wait, context check for Past Perfect)",
        options: ["will have worked", "had worked", "would work", "worked"],
        answer: 1,
        explanation: "(Revisi Konteks Soal ke Past): 'By the time the project WAS finished, we HAD WORKED on it for two years.' Dalam konteks soal Past Perfect, kita melihat durasi yang selesai di masa lalu."
    },
    {
        question: "Before he was caught, the spy ______ sensitive information to the enemy for years.",
        options: ["passed", "was passing", "had passed", "has passed"],
        answer: 2,
        explanation: "Meskipun ada durasi 'for years' (yang bisa memicu continuous), 'had passed' menekankan pada penyelesaian aksi transfer data tersebut sebelum tertangkap."
    },
    {
        question: "They ______ to win the game, but the referee made a controversial call.",
        options: ["hoped", "have hoped", "had hoped", "hoping"],
        answer: 2,
        explanation: "'Had hoped' menyiratkan harapan yang tidak terwujud (unfulfilled hope) di masa lalu. Ini memberikan nuansa kekecewaan yang lebih kuat daripada 'hoped'."
    },
    {
        question: "Whatever ______ to the missing documents remains a mystery.",
        options: ["happened", "has happened", "had happened", "was happening"],
        answer: 2,
        explanation: "Kita membicarakan misteri di masa sekarang (remains) atau masa lalu tentang apa yang SUDAH terjadi sebelumnya. 'Had happened' menekankan kejadian yang mendahului status 'hilang' tersebut."
    },
    {
        question: "Had I known it was going to rain, I ______ my umbrella.",
        options: ["would bring", "will bring", "would have brought", "had brought"],
        answer: 2,
        explanation: "Ini adalah bentuk Inversi dari Third Conditional. 'If I had known' bisa dipersingkat menjadi 'Had I known'. Pasangannya tetap 'would have + V3'."
    },
    {
        question: "She was furious because her brother ______ her diary to his friends.",
        options: ["read", "was reading", "had read", "has read"],
        answer: 2,
        explanation: "Kemarahan (was furious) dipicu oleh aksi yang sudah selesai dilakukan (membaca diary). 'Had read' menunjukkan aksi itu komplit dan menjadi penyebab utama."
    },
    {
        question: "Only after I ______ the contract did I notice the fine print.",
        options: ["signed", "have signed", "had signed", "sign"],
        answer: 2,
        explanation: "Pola 'Only after' yang diikuti inversi di klausa utama (did I notice) membutuhkan Past Perfect di klausa awal untuk menunjukkan urutan waktu yang ketat."
    }
];