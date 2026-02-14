const questionsSource = [
    // --- TO BE (AM, IS, ARE) ---
    {
        question: "I ______ visit my grandmother next week.",
        options: ["will", "will be", "am", "going to"],
        answer: 0,
        explanation: "Rumus dasar Simple Future adalah 'Will + Verb 1'. Di sini verb utamanya adalah 'visit'."
    },
    {
        question: "She ______ a new laptop tomorrow.",
        options: ["buy", "will buy", "buying", "will buys"],
        answer: 1,
        explanation: "Setelah 'will', kata kerja harus berupa 'Bare Infinitive' (V1 murni). Tidak boleh ada tambahan -s, -ing, atau -ed."
    },
    {
        question: "They ______ late for the meeting.",
        options: ["will be", "will", "are", "be"],
        answer: 0,
        explanation: "Karena 'late' adalah kata sifat (adjective), kita membutuhkan 'be' setelah 'will'. Rumus: Will + be + Adjective."
    },
    {
        question: "He ______ come to the party tonight.",
        options: ["won't", "don't", "isn't", "not will"],
        answer: 0,
        explanation: "Bentuk negatif dari 'will' adalah 'will not' atau disingkat 'won't'."
    },
    {
        question: "______ you help me with this box?",
        options: ["Does", "Are", "Will", "Is"],
        answer: 2,
        explanation: "Ini adalah permintaan tolong (request). Kata tanya diawali dengan Modal 'Will'."
    },
    {
        question: "We ______ wait here until you return.",
        options: ["will", "are", "going to", "will to"],
        answer: 0,
        explanation: "Kalimat janji atau keputusan spontan menggunakan 'will'. Tidak perlu 'to' setelah will."
    },
    {
        question: "It ______ rain tomorrow.",
        options: ["wills", "will", "is will", "willing"],
        answer: 1,
        explanation: "Modal 'will' tidak pernah berubah bentuk meskipun subjeknya 'It' (singular)."
    },
    {
        question: "The teacher ______ explain the lesson soon.",
        options: ["will explains", "will explain", "will explaining", "explain"],
        answer: 1,
        explanation: "Aturan: Will + V1. 'Explains' dan 'explaining' salah jika diletakkan langsung setelah will."
    },
    {
        question: "I promise I ______ tell anyone your secret.",
        options: ["not", "won't", "am not", "don't"],
        answer: 1,
        explanation: "Untuk janji (promise), kita menggunakan 'will'. Bentuk negatifnya adalah 'won't'."
    },
    {
        question: "Do you think they ______ win the match?",
        options: ["will", "are", "going", "do"],
        answer: 0,
        explanation: "Untuk prediksi berdasarkan opini (menggunakan 'think'), kita menggunakan 'will'."
    },
    {
        question: "Maybe she ______ call you later.",
        options: ["is going", "will", "wants", "shall"],
        answer: 1,
        explanation: "'Maybe' menandakan ketidakpastian, jadi 'will' lebih tepat daripada 'is going to'."
    },
    {
        question: "We ______ be happy to see you.",
        options: ["will", "are", "can", "did"],
        answer: 0,
        explanation: "Mengekspresikan perasaan di masa depan: Will + be + Adjective (happy)."
    },
    {
        question: "The sun ______ rise at 6 AM.",
        options: ["will", "going to", "is", "wills"],
        answer: 0,
        explanation: "Fakta alam di masa depan menggunakan 'will'."
    },
    {
        question: "______ pass the salt, please?",
        options: ["You will", "Will you", "Do you", "Are you"],
        answer: 1,
        explanation: "Kalimat tanya (permintaan) membalikkan posisi subjek: Will + Subject + Verb."
    },
    {
        question: "I ______ probably stay at home.",
        options: ["am", "will", "going to", "wont"],
        answer: 1,
        explanation: "'Probably' berpasangan kuat dengan 'will' karena menunjukkan prediksi yang belum 100% pasti."
    },
    {
        question: "Don't worry, I ______ forget to lock the door.",
        options: ["won't", "not will", "am not", "don't"],
        answer: 0,
        explanation: "Bentuk negatif future yang benar adalah 'won't' (will not)."
    },
    {
        question: "The concert ______ start in 5 minutes.",
        options: ["will", "is", "going", "wants"],
        answer: 0,
        explanation: "Jadwal atau prediksi waktu dekat menggunakan 'will' + verb 'start'."
    },
    {
        question: "I am hungry. I ______ make a sandwich.",
        options: ["will", "am going to", "go to", "will be"],
        answer: 0,
        explanation: "Keputusan spontan (saat berbicara baru memutuskan) menggunakan 'will'."
    },
    {
        question: "He ______ be a great doctor one day.",
        options: ["will", "is", "going", "wanna"],
        answer: 0,
        explanation: "Prediksi umum tentang masa depan seseorang menggunakan 'will'."
    },
    {
        question: "If it rains, we ______ cancel the picnic.",
        options: ["will", "are", "go to", "would"],
        answer: 0,
        explanation: "Conditional Sentence Type 1 (If Present, Future). Pasangannya adalah 'will'."
    },
    {
        question: "I ______ going to buy a new car next month.",
        options: ["will", "am", "is", "are"],
        answer: 1,
        explanation: "Rumus 'be going to': Subject 'I' pasangannya adalah to be 'am'."
    },
    {
        question: "Look at those dark clouds! It ______ rain.",
        options: ["will", "is going to", "shall", "won't"],
        answer: 1,
        explanation: "Prediksi dengan BUKTI fisik (awan gelap) menggunakan 'be going to'."
    },
    {
        question: "They ______ going to visit Bali next holiday.",
        options: ["is", "am", "are", "will"],
        answer: 2,
        explanation: "Subjek 'They' (jamak) menggunakan to be 'are'."
    },
    {
        question: "She is ______ to cook dinner tonight.",
        options: ["go", "going", "will", "gone"],
        answer: 1,
        explanation: "Struktur: Subject + to be + GOING + to + V1."
    },
    {
        question: "We have bought the tickets. We ______ watch the movie.",
        options: ["will", "are going to", "will be", "go to"],
        answer: 1,
        explanation: "Karena tiket sudah dibeli (rencana matang), 'are going to' lebih tepat."
    },
    {
        question: "What ______ you going to do?",
        options: ["are", "will", "is", "do"],
        answer: 0,
        explanation: "Wh-question + to be + Subject + going to. Subjek 'you' butuh 'are'."
    },
    {
        question: "He ______ not going to play football.",
        options: ["are", "am", "is", "will"],
        answer: 2,
        explanation: "Subjek tunggal (He) menggunakan to be 'is'."
    },
    {
        question: "______ she going to come with us?",
        options: ["Are", "Is", "Will", "Does"],
        answer: 1,
        explanation: "Pertanyaan Yes/No dengan 'going to'. Subjek 'She' membutuhkan 'Is'."
    },
    {
        question: "I am going ______ study harder.",
        options: ["to", "for", "at", "will"],
        answer: 0,
        explanation: "Frasa yang benar adalah 'going TO' + Verb 1."
    },
    {
        question: "My parents ______ going to retire soon.",
        options: ["is", "are", "will", "am"],
        answer: 1,
        explanation: "'My parents' adalah jamak, jadi menggunakan 'are'."
    },
    {
        question: "The car is broken. It is ______ to crash!",
        options: ["will", "go", "going", "goes"],
        answer: 2,
        explanation: "Prediksi dengan bukti (mobil rusak) -> 'is going to'."
    },
    {
        question: "Why ______ you going to sell your house?",
        options: ["do", "did", "are", "will"],
        answer: 2,
        explanation: "Wh-question + to be (are) + subject (you) + going to."
    },
    {
        question: "I ______ going to tell him the truth.",
        options: ["am not", "not", "don't", "won't"],
        answer: 0,
        explanation: "Negatif 'be going to'. I + am + not + going to."
    },
    {
        question: "Are you going to ______ the exam?",
        options: ["taking", "take", "took", "taken"],
        answer: 1,
        explanation: "Setelah 'to', kata kerja harus V1 murni (take)."
    },
    {
        question: "Look at the time! We ______ going to be late.",
        options: ["will", "are", "is", "am"],
        answer: 1,
        explanation: "Subjek 'We' menggunakan 'are'."
    },
    {
        question: "Who is ______ to drive the car?",
        options: ["will", "going", "go", "gone"],
        answer: 1,
        explanation: "Pola kalimat 'Who is going to...'"
    },
    {
        question: "I feel terrible. I think I ______ going to be sick.",
        options: ["will", "am", "is", "are"],
        answer: 1,
        explanation: "Ada bukti fisik (feel terrible) dan struktur kalimatnya menggunakan 'going to', jadi harus pakai 'am'."
    },
    {
        question: "They are ______ to build a new bridge here.",
        options: ["going", "go", "will", "planning"],
        answer: 0,
        explanation: "Are + Going + To + V1."
    },
    {
        question: "______ is going to win the race?",
        options: ["Who", "When", "Which", "Why"],
        answer: 0,
        explanation: "Menanyakan subjek orang -> 'Who'."
    },
    {
        question: "It is ______ to be a nice day.",
        options: ["go", "will", "going", "wanna"],
        answer: 2,
        explanation: "Prediksi cuaca dengan tanda-tanda -> 'It is going to be'."
    },
    {
        question: "A: 'The phone is ringing.' B: 'I ______ get it.'",
        options: ["am going to", "will", "am", "go to"],
        answer: 1,
        explanation: "Keputusan spontan saat berbicara menggunakan 'will'."
    },
    {
        question: "A: 'Why did you buy flour?' B: 'I ______ make a cake.'",
        options: ["will", "am going to", "am", "won't"],
        answer: 1,
        explanation: "Karena sudah membeli tepung (rencana), jadi 'am going to'."
    },
    {
        question: "In 2050, people ______ fly cars.",
        options: ["are going to", "will", "are", "doing"],
        answer: 1,
        explanation: "Prediksi jauh di masa depan tanpa bukti nyata saat ini menggunakan 'will'."
    },
    {
        question: "Watch out! You ______ fall!",
        options: ["will", "are going to", "is going to", "won't"],
        answer: 1,
        explanation: "Peringatan bahaya yang akan segera terjadi (ada bukti situasi bahaya) -> 'are going to'."
    },
    {
        question: "I ______ probably see you tomorrow.",
        options: ["am going to", "will", "am", "do"],
        answer: 1,
        explanation: "Kata 'probably' (kemungkinan) lebih cocok dengan 'will'."
    },
    {
        question: "Next year, I ______ turn 25.",
        options: ["will", "going to", "am", "want"],
        answer: 0,
        explanation: "Fakta di masa depan (umur) menggunakan 'will'."
    },
    {
        question: "Can you keep a secret? I ______ tell anyone.",
        options: ["am not going to", "won't", "don't", "didn't"],
        answer: 1,
        explanation: "Janji (Promise) menggunakan 'won't'."
    },
    {
        question: "I hope she ______ pass the exam.",
        options: ["is going to", "will", "does", "is"],
        answer: 1,
        explanation: "Kata 'Hope' (harapan) biasanya diikuti oleh 'will'."
    },
    {
        question: "Are you busy? I ______ give you a hand.",
        options: ["am going to", "will", "am", "can't"],
        answer: 1,
        explanation: "Menawarkan bantuan (Offer) secara spontan menggunakan 'will'."
    },
    {
        question: "My flight ______ at 9 PM.",
        options: ["will leaves", "leaving", "leaves", "is going to leaves"],
        answer: 2,
        explanation: "Jadwal resmi (timetable) pesawat/kereta sering menggunakan Simple Present (leaves)."
    },
    {
        question: "We ______ have a meeting next Monday at 10 AM.",
        options: ["will", "are going to", "shall", "won't"],
        answer: 1,
        explanation: "Jadwal meeting spesifik biasanya sudah direncanakan -> 'are going to'."
    },
    {
        question: "Wait here. I ______ get my car.",
        options: ["am going to", "will", "go to", "am"],
        answer: 1,
        explanation: "Keputusan saat itu juga (spontan) -> 'will'."
    },
    {
        question: "Look at the traffic! We ______ miss our flight.",
        options: ["will", "are going to", "shall", "go to"],
        answer: 1,
        explanation: "Bukti fisik (macet) -> 'are going to'."
    },
    {
        question: "I think it ______ snow later.",
        options: ["will", "is going to", "snows", "snowing"],
        answer: 0,
        explanation: "Prediksi opini (think) -> 'will'."
    },
    {
        question: "What ______ happen if I press this button?",
        options: ["is going to", "will", "does", "is"],
        answer: 1,
        explanation: "Menanyakan konsekuensi (Condition) -> 'will'."
    },
    {
        question: "I ______ always love you.",
        options: ["am going to", "will", "am", "do"],
        answer: 1,
        explanation: "Janji/Perasaan abadi -> 'will'."
    },
    {
        question: "______ we go out for dinner tonight?",
        options: ["Will", "Shall", "Do", "Are"],
        answer: 1,
        explanation: "Saran (Suggestion) untuk 'We' atau 'I' menggunakan 'Shall'."
    },
    {
        question: "She ______ be very angry when she finds out.",
        options: ["is going to", "will", "is", "has"],
        answer: 1,
        explanation: "Prediksi reaksi seseorang -> 'will'."
    },
    {
        question: "I ______ visit Paris one day.",
        options: ["am going to", "will", "go to", "visiting"],
        answer: 1,
        explanation: "Impian yang belum pasti waktunya ('one day') -> 'will'."
    },
    {
        question: "They ______ move to a new house next week. Everything is packed.",
        options: ["will", "are going to", "shall", "wills"],
        answer: 1,
        explanation: "Sudah dipacking (Prepared plan) -> 'are going to'."
    },
    {
        question: "Tomorrow is Sunday. I ______ work.",
        options: ["won't", "not will", "don't will", "am not"],
        answer: 0,
        explanation: "Besok Minggu, jadi prediksi negatif 'tidak akan' -> 'won't'."
    },
    {
        question: "When ______ you finish the project?",
        options: ["will", "are", "do", "going to"],
        answer: 0,
        explanation: "Wh-question dengan will: When + Will + Subject + V1."
    },
    {
        question: "He ______ probably not come.",
        options: ["is", "will", "does", "has"],
        answer: 1,
        explanation: "Probably + will."
    },
    {
        question: "Be careful or you ______ hurt yourself.",
        options: ["will", "are going to", "did", "do"],
        answer: 0,
        explanation: "Ancaman/Peringatan -> 'will'."
    },
    {
        question: "I don't think she ______ like the gift.",
        options: ["will", "is going to", "does", "is"],
        answer: 0,
        explanation: "Opini (don't think) -> 'will'."
    },
    {
        question: "The sky is blue. It ______ rain today.",
        options: ["won't", "isn't going to", "will", "not going to"],
        answer: 1,
        explanation: "Bukti fisik (langit biru) untuk prediksi negatif -> 'isn't going to'."
    },
    {
        question: "My bag is heavy. ______ you carry it for me?",
        options: ["Are", "Will", "Do", "Is"],
        answer: 1,
        explanation: "Permintaan tolong -> 'Will'."
    },
    {
        question: "I ______ have a steak, please.",
        options: ["am going to", "will", "shall", "am"],
        answer: 1,
        explanation: "Memesan makanan di restoran (keputusan saat itu) -> 'will'."
    },
    {
        question: "Next month, we ______ been married for 10 years.",
        options: ["will have", "will has", "are going to", "will"],
        answer: 0,
        explanation: "Future Perfect (durasi di masa depan) -> 'will have'."
    },
    {
        question: "I expect he ______ arrive soon.",
        options: ["will", "is going to", "is", "does"],
        answer: 0,
        explanation: "Kata 'Expect' (berharap/menduga) -> 'will'."
    },
    {
        question: "They ______ until the end.",
        options: ["will stay", "will staying", "staying", "stays"],
        answer: 0,
        explanation: "Will + V1 (stay)."
    },
    {
        question: "I ______ accept your offer.",
        options: ["am not going to", "will not", "won't to", "don't will"],
        answer: 1,
        explanation: "Penolakan formal -> 'will not' (atau won't)."
    },
    {
        question: "Where ______ spend your holiday?",
        options: ["will you", "you will", "are you", "you are"],
        answer: 0,
        explanation: "Kalimat tanya: Auxiliary (will) sebelum Subject (you)."
    },
    {
        question: "The company ______ launch a new product.",
        options: ["is going to", "will be", "going to", "are going to"],
        answer: 0,
        explanation: "Company (singular) + is going to."
    },
    {
        question: "I'm sure you ______ enjoy the film.",
        options: ["will", "are going to", "maybe", "wanna"],
        answer: 0,
        explanation: "'I'm sure' (yakin) biasanya diikuti 'will'."
    },
    {
        question: "______ I help you with the luggage?",
        options: ["Will", "Shall", "Do", "Am"],
        answer: 1,
        explanation: "Menawarkan bantuan (Offer) menggunakan 'Shall I...?'."
    },
    {
        question: "Look! The bus ______ leave!",
        options: ["is going to", "will", "shall", "wants"],
        answer: 0,
        explanation: "Bukti visual kejadian segera -> 'is going to'."
    },
    {
        question: "If you study hard, you ______ pass.",
        options: ["will", "going to", "are", "have"],
        answer: 0,
        explanation: "Conditional type 1 -> 'will'."
    },
    {
        question: "We ______ not need any more help.",
        options: ["will", "are", "do", "have"],
        answer: 0,
        explanation: "Kalimat negatif formal 'will not need'."
    },
    {
        question: "She ______ be famous someday.",
        options: ["will", "is going", "wants", "shall"],
        answer: 0,
        explanation: "Prediksi masa depan jauh -> 'will'."
    },
    {
        question: "I promise I ______ be late again.",
        options: ["won't", "am not", "don't", "will"],
        answer: 0,
        explanation: "Janji tidak akan melakukan sesuatu -> 'won't'."
    },
    {
        question: "The meeting ______ take place in Room B.",
        options: ["will", "is going", "shall", "wants"],
        answer: 0,
        explanation: "Informasi masa depan -> 'will'."
    },
    {
        question: "______ you please turn down the volume?",
        options: ["Will", "Are", "Do", "Is"],
        answer: 0,
        explanation: "Permintaan sopan (Request) -> 'Will'."
    },
    {
        question: "I ______ see the doctor this afternoon. I have an appointment.",
        options: ["am going to", "will", "shall", "go to"],
        answer: 0,
        explanation: "Appointment (janji temu resmi) -> 'am going to'."
    },
    {
        question: "He ______ buy the house, it's too expensive.",
        options: ["won't", "isn't going to", "not will", "don't"],
        answer: 0,
        explanation: "Keputusan menolak karena harga -> 'won't'."
    },
    {
        question: "Don't touch that! You ______ burn yourself.",
        options: ["will", "are going to", "shall", "do"],
        answer: 0,
        explanation: "Peringatan spontan -> 'will'."
    },
    {
        question: "I ______ call you as soon as I arrive.",
        options: ["will", "am going to", "am", "do"],
        answer: 0,
        explanation: "Janji/Tindakan segera di masa depan -> 'will'."
    },
    {
        question: "Who ______ be the next president?",
        options: ["will", "is", "going to", "does"],
        answer: 0,
        explanation: "Pertanyaan prediksi umum -> 'will'."
    },
    {
        question: "We ______ run out of gas soon.",
        options: ["are going to", "will", "shall", "go to"],
        answer: 0,
        explanation: "Prediksi dengan bukti (indikator bensin) -> 'are going to'."
    },
    {
        question: "I ______ get some water. Do you want some?",
        options: ["will", "am going to", "shall", "am"],
        answer: 0,
        explanation: "Tawaran/Aksi spontan -> 'will'."
    },
    {
        question: "She ______ never forgive him.",
        options: ["will", "is going to", "shall", "has"],
        answer: 0,
        explanation: "Pernyataan tegas tentang masa depan -> 'will'."
    },
    {
        question: "They ______ start the project without us.",
        options: ["won't", "aren't going", "not will", "don't"],
        answer: 0,
        explanation: "Prediksi negatif -> 'won't'."
    },
    {
        question: "______ it rain this evening?",
        options: ["Will", "Is", "Does", "Has"],
        answer: 0,
        explanation: "Tanya prediksi cuaca -> 'Will'."
    },
    {
        question: "I think the exam ______ be difficult.",
        options: ["will", "is going to", "shall", "is"],
        answer: 0,
        explanation: "Opini (think) -> 'will'."
    },
    {
        question: "Look! That tree ______ fall!",
        options: ["is going to", "will", "shall", "wants"],
        answer: 0,
        explanation: "Bukti visual jelas -> 'is going to'."
    },
    {
        question: "I ______ probably stay here.",
        options: ["will", "am going to", "am", "do"],
        answer: 0,
        explanation: "Probably -> 'will'."
    },
    {
        question: "We ______ see what happens.",
        options: ["will", "are going to", "shall", "do"],
        answer: 0,
        explanation: "Ungkapan umum 'We will see' (Kita lihat saja nanti)."
    },
    {
        question: "______ you marry me?",
        options: ["Will", "Are", "Do", "Shall"],
        answer: 0,
        explanation: "Lamaran (Proposal) -> 'Will'."
    },
    {
        question: "I ______ be back in a minute.",
        options: ["will", "am going to", "shall", "am"],
        answer: 0,
        explanation: "Janji kembali cepat -> 'will'."
    },
    {
        question: "Happy New Year! I ______ quit smoking.",
        options: ["am going to", "will", "shall", "am"],
        answer: 0,
        explanation: "Resolusi Tahun Baru yang terencana -> 'am going to'."
    }
];