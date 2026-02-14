const questionsSource = [
    // --- LEVEL: BEGINNER (20 Soal) ---
    // Fokus: Struktur dasar Will/Be going to + Verb 1 (Base Form)

    {
        question: "I ______ call you later.",
        options: ["will", "am", "going to", "will be"],
        answer: 0,
        explanation: "Rumus dasar Simple Future adalah Subject + will + Verb 1. Jadi jawabannya 'will'."
    },
    {
        question: "She ______ to the party tonight.",
        options: ["will comes", "will come", "will coming", "coming"],
        answer: 1,
        explanation: "Setelah modal 'will', kata kerja harus dalam bentuk dasar (V1) tanpa tambahan -s/-es atau -ing. Jadi 'will come'."
    },
    {
        question: "They ______ visit their grandmother next week.",
        options: ["are going to", "will going to", "is going to", "going to"],
        answer: 0,
        explanation: "Untuk struktur 'be going to', subjek 'They' berpasangan dengan to be 'are'. Jadi 'are going to'."
    },
    {
        question: "He ______ buy a new laptop soon.",
        options: ["is going to", "are going to", "will going to", "am going to"],
        answer: 0,
        explanation: "Subjek tunggal 'He' menggunakan to be 'is' dalam struktur 'is going to'."
    },
    {
        question: "______ you help me with this box?",
        options: ["Are", "Will", "Is", "Does"],
        answer: 1,
        explanation: "Kalimat tanya untuk permintaan (request) di masa depan menggunakan 'Will' di awal kalimat."
    },
    {
        question: "We ______ late for the movie.",
        options: ["will be", "will", "are will", "being"],
        answer: 0,
        explanation: "Jika tidak ada kata kerja aksi, kita membutuhkan 'be' setelah 'will' sebagai kata kerja bantu. 'Will be late' (akan terlambat)."
    },
    {
        question: "I think it ______ rain tomorrow.",
        options: ["will", "is", "going", "wills"],
        answer: 0,
        explanation: "Untuk prediksi umum tanpa bukti fisik yang kuat saat ini, kita biasanya menggunakan 'will'."
    },
    {
        question: "She ______ not go to school tomorrow.",
        options: ["will", "is", "does", "has"],
        answer: 0,
        explanation: "Bentuk negatif Simple Future menggunakan 'will not' (won't). Di sini opsi 'will' melengkapi 'not go'."
    },
    {
        question: "______ they going to play soccer?",
        options: ["Will", "Are", "Do", "Is"],
        answer: 1,
        explanation: "Dalam struktur 'be going to', kalimat tanya dimulai dengan To Be. Karena subjeknya 'they', gunakan 'Are'."
    },
    {
        question: "Look! The bus ______ leave.",
        options: ["is going to", "will", "shall", "are going to"],
        answer: 0,
        explanation: "Subjek 'The bus' (tunggal) menggunakan 'is going to'. Struktur ini tepat karena ada tanda yang terlihat (Look!)."
    },
    {
        question: "I promise I ______ tell anyone.",
        options: ["won't", "not will", "am not", "don't"],
        answer: 0,
        explanation: "Untuk janji (promise), kita menggunakan 'will'. Bentuk negatif dari will adalah 'won't' (will not)."
    },
    {
        question: "The sun ______ rise at 6 AM.",
        options: ["will", "is", "going to", "shall"],
        answer: 0,
        explanation: "Fakta alam atau kejadian masa depan yang pasti biasanya menggunakan 'will'."
    },
    {
        question: "______ I carry your bag?",
        options: ["Shall", "Will", "Do", "Am"],
        answer: 0,
        explanation: "Khusus untuk subjek 'I' dan 'We', kata 'Shall' sering digunakan untuk menawarkan bantuan (offer) dalam bentuk tanya formal."
    },
    {
        question: "Next year, I ______ be twenty years old.",
        options: ["will", "am going", "want", "am"],
        answer: 0,
        explanation: "Untuk fakta usia di masa depan yang tidak bisa diubah, gunakan 'will'."
    },
    {
        question: "It is very hot. I ______ open the window.",
        options: ["will", "am going to", "shall", "go to"],
        answer: 0,
        explanation: "Keputusan spontan (saat berbicara) karena panas, menggunakan 'will'."
    },
    {
        question: "My parents ______ stay at a hotel.",
        options: ["are going to", "is going to", "will going to", "going to"],
        answer: 0,
        explanation: "Subjek jamak 'My parents' menggunakan 'are' dalam pola 'are going to'."
    },
    {
        question: "Don't worry, you ______ pass the exam.",
        options: ["will", "are going", "is going to", "shall"],
        answer: 0,
        explanation: "Kata-kata penghibur atau prediksi harapan (Don't worry) biasanya diikuti 'will'."
    },
    {
        question: "We ______ have a meeting at 10.",
        options: ["will", "are", "going", "is"],
        answer: 0,
        explanation: "Struktur dasar: Subject + will + V1 (have)."
    },
    {
        question: "______ she be angry with me?",
        options: ["Will", "Is", "Does", "Has"],
        answer: 0,
        explanation: "Pertanyaan prediksi tentang keadaan/perasaan (adjective 'angry') menggunakan pola 'Will + S + be + Adj?'."
    },
    {
        question: "I ______ probably go to Bali next year.",
        options: ["will", "am", "going to", "must"],
        answer: 0,
        explanation: "Kata 'probably' (mungkin) sangat sering dipasangkan dengan 'will'."
    },

    // --- LEVEL: INTERMEDIATE (20 Soal) ---
    // Fokus: Perbedaan Will vs Be Going To (Plan vs Spontaneous vs Prediction), Time Expressions.

    {
        question: "Look at those dark clouds! It ______ rain.",
        options: ["is going to", "will", "shall", "wants to"],
        answer: 0,
        explanation: "Prediksi berdasarkan BUKTI FISIK yang terlihat sekarang (dark clouds) harus menggunakan 'be going to'."
    },
    {
        question: "Why did you buy flour and eggs? I ______ bake a cake.",
        options: ["will", "am going to", "shall", "am will"],
        answer: 1,
        explanation: "Ini adalah RENCANA yang sudah dipersiapkan sebelumnya (sudah beli bahan), jadi gunakan 'am going to'."
    },
    {
        question: "The phone is ringing. I ______ answer it.",
        options: ["will", "am going to", "shall", "go to"],
        answer: 0,
        explanation: "Keputusan SPONTAN yang dibuat detik itu juga (saat telepon berbunyi) menggunakan 'will'."
    },
    {
        question: "I feel sick. I think I ______ vomit.",
        options: ["will", "am going to", "shall", "go to"],
        answer: 1,
        explanation: "Meskipun ada 'I think', frasa 'I feel sick' adalah bukti fisik/sensasi internal yang kuat bahwa sesuatu akan segera terjadi. 'Am going to' lebih tepat untuk kejadian yang hampir pasti terjadi berdasarkan kondisi saat ini."
    },
    {
        question: "We ______ fly to Tokyo next Monday. Here are the tickets.",
        options: ["will", "are going to", "shall", "go to"],
        answer: 1,
        explanation: "Karena tiket sudah dibeli, ini adalah rencana pasti (arrangement). 'Are going to' lebih tepat daripada 'will'."
    },
    {
        question: "I hope the weather ______ be nice tomorrow.",
        options: ["will", "is going to", "shall", "is"],
        answer: 0,
        explanation: "Kata kerja 'hope' (berharap) biasanya diikuti oleh 'will' karena sifatnya prediksi/harapan tak pasti."
    },
    {
        question: "Oh no! I forgot my wallet. I ______ pay.",
        options: ["will", "won't", "can't", "am not going to"],
        answer: 2,
        explanation: "Konteks: Lupa dompet berarti TIDAK BISA bayar (kemampuan). Namun jika dipaksa memilih bentuk future untuk menyatakan penolakan/ketidaksanggupan masa depan, 'won't' bisa dipakai, tapi 'can't' (tidak bisa) paling logis secara makna. Dalam konteks grammar Future, jika pilihannya 'won't' vs 'not going to', 'won't' lebih pas untuk situasi spontan. (Catatan: Di soal ini opsi 'can't' adalah jawaban paling logis secara semantik)."
    },
    {
        question: "Watch out! You ______ fall!",
        options: ["will", "are going to", "shall", "go to"],
        answer: 1,
        explanation: "Peringatan akan bahaya yang SEGERA terjadi berdasarkan situasi saat ini (terlihat akan jatuh) menggunakan 'are going to'."
    },
    {
        question: "I don't think she ______ like the present.",
        options: ["will", "is going to", "shall", "wants"],
        answer: 0,
        explanation: "Prediksi subjektif (opinion) dengan 'I don't think' menggunakan 'will'."
    },
    {
        question: "What ______ you ______ do when you retire?",
        options: ["will / do", "are / going to", "do / will", "are / will"],
        answer: 1,
        explanation: "Menanyakan rencana jangka panjang (pensiun) menggunakan 'are going to'."
    },
    {
        question: "If you help me, I ______ buy you lunch.",
        options: ["will", "am going to", "shall", "would"],
        answer: 0,
        explanation: "Conditional Sentence Type 1. Klausa hasil (result clause) menggunakan 'will' untuk janji/tawaran."
    },
    {
        question: "A: 'We run out of sugar.' B: 'Okay, I ______ buy some.'",
        options: ["will", "am going to", "buy", "am buying"],
        answer: 0,
        explanation: "Orang B baru tahu gula habis, jadi dia membuat keputusan SPONTAN. Gunakan 'will'."
    },
    {
        question: "A: 'Why are you putting on your coat?' B: 'I ______ go to the shop.'",
        options: ["will", "am going to", "shall", "go to"],
        answer: 1,
        explanation: "Orang B sudah bersiap-siap (putting on coat), berarti niat/rencana sudah ada sebelum ditanya. Gunakan 'am going to'."
    },
    {
        question: "In 2050, people ______ probably buy everything online.",
        options: ["will", "are going to", "shall", "must"],
        answer: 0,
        explanation: "Prediksi jauh ke masa depan tanpa bukti fisik saat ini menggunakan 'will'."
    },
    {
        question: "I ______ see the doctor on Friday morning. I have an appointment.",
        options: ["will", "am going to", "shall", "go to"],
        answer: 1,
        explanation: "Adanya 'appointment' (janji temu) menandakan rencana yang sudah diatur. 'Am going to' (atau Present Continuous) adalah pilihan tepat."
    },
    {
        question: "Do you think it ______ snow tonight?",
        options: ["will", "is going to", "shall", "can"],
        answer: 0,
        explanation: "Pertanyaan prediksi umum (opinion) menggunakan 'will'."
    },
    {
        question: "I'm sure they ______ win the match.",
        options: ["will", "are going to", "shall", "won't"],
        answer: 0,
        explanation: "Kata 'I'm sure' (yakin) mengekspresikan opini/keyakinan pembicara, jadi menggunakan 'will'."
    },
    {
        question: "Are you ______ visit John in the hospital?",
        options: ["going to", "will", "go to", "going"],
        answer: 0,
        explanation: "Struktur kalimat tanya 'Are you...' menuntut kelanjutan 'going to' untuk membentuk Future Tense. Tidak bisa 'Are you will'."
    },
    {
        question: "Maybe I ______ stay at home tonight.",
        options: ["will", "am going to", "shall", "must"],
        answer: 0,
        explanation: "Kata 'Maybe' menandakan ketidakpastian, yang lebih cocok dengan 'will' daripada 'going to' (rencana pasti)."
    },
    {
        question: "She ______ turn 17 next month.",
        options: ["will", "is going to", "shall", "wants"],
        answer: 0,
        explanation: "Sekali lagi, fakta masa depan (future fact) seperti umur menggunakan 'will'."
    },

    // --- LEVEL: EXPERT (10 Soal) ---
    // Fokus: Time Clauses (When/After/Before), Shall, Formal English, dan pengecualian.

    {
        question: "I will call you when I ______ home.",
        options: ["will get", "get", "am getting", "got"],
        answer: 1,
        explanation: "Aturan Time Clause: Setelah kata sambung waktu (when, before, after, as soon as), kita TIDAK BOLEH menggunakan 'will'. Gunakan Present Simple ('get') untuk makna masa depan."
    },
    {
        question: "Please wait here until the doctor ______ ready.",
        options: ["will be", "is", "is going to be", "was"],
        answer: 1,
        explanation: "Sama seperti 'when', kata 'until' diikuti Present Simple ('is') meskipun konteksnya masa depan."
    },
    {
        question: "Unless he ______, he will fail the exam.",
        options: ["studies", "will study", "studied", "is going to study"],
        answer: 0,
        explanation: "Dalam 'If clause' atau 'Unless' (Conditional Type 1), gunakan Present Simple ('studies'), bukan 'will'."
    },
    {
        question: "As soon as we ______ the tickets, we will let you know.",
        options: ["buy", "will buy", "bought", "are buying"],
        answer: 0,
        explanation: "Time clause dengan 'As soon as' menggunakan Present Simple ('buy')."
    },
    {
        question: "______ we go to the beach or the mountains?",
        options: ["Shall", "Will", "Are", "Do"],
        answer: 0,
        explanation: "Menggunakan 'Shall' untuk meminta pendapat/saran (suggestion) dengan subjek 'we'. 'Will' terdengar kaku atau salah dalam konteks meminta saran pilihan."
    },
    {
        question: "The conference ______ begin at 9:00 AM sharp.",
        options: ["will", "is to", "shall", "going to"],
        answer: 0,
        explanation: "Untuk jadwal resmi (timetable/schedule), 'Simple Present' (begins) atau 'Will' bisa digunakan. Di sini 'will' adalah opsi terbaik yang tersedia untuk menyatakan kepastian jadwal."
    },
    {
        question: "I won't go out if it ______.",
        options: ["rains", "will rain", "raining", "rained"],
        answer: 0,
        explanation: "Conditional Type 1: If + Present Simple (rains), Main Clause + Will."
    },
    {
        question: "He ______ help you, I'm afraid. He is too busy.",
        options: ["won't", "will", "isn't going to", "doesn't"],
        answer: 0,
        explanation: "Penolakan (refusal) di masa depan sering dinyatakan dengan 'won't'. 'He won't help you' (Dia tidak mau/tidak akan membantumu)."
    },
    {
        question: "By the time you arrive, I ______ cooked dinner. (Future Perfect context but checking Will usage)",
        options: ["will have", "will", "have", "had"],
        answer: 0,
        explanation: "Meskipun ini Future Perfect, dasarnya adalah 'will'. 'Will have cooked' menunjukkan aksi selesai di masa depan."
    },
    {
        question: "Let's go to the park, ______ we?",
        options: ["shall", "will", "do", "don't"],
        answer: 0,
        explanation: "Question Tag untuk ajakan 'Let's' adalah 'shall we?'."
    }
];