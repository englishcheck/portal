const questionsSource = [
    // --- TO BE (AM, IS, ARE) ---
    {
        question: "I ______ a student.",
        options: ["is", "are", "am", "were"],
        answer: 2,
        explanation: "Untuk subjek 'I' (saya), to be yang digunakan dalam bentuk present tense selalu 'am'."
    },
    {
        question: "She ______ my sister.",
        options: ["are", "is", "am", "be"],
        answer: 1,
        explanation: "Subjek 'She' (dia perempuan) adalah tunggal, jadi menggunakan to be 'is'."
    },
    {
        question: "They ______ happy.",
        options: ["is", "am", "was", "are"],
        answer: 3,
        explanation: "Subjek 'They' (mereka) adalah jamak (banyak orang), jadi menggunakan to be 'are'."
    },
    {
        question: "He ______ a doctor.",
        options: ["is", "are", "am", "were"],
        answer: 0,
        explanation: "Subjek 'He' (dia laki-laki) adalah tunggal, maka pasangannya adalah 'is'."
    },
    {
        question: "We ______ friends.",
        options: ["am", "is", "are", "was"],
        answer: 2,
        explanation: "Subjek 'We' (kita/kami) adalah jamak, jadi menggunakan to be 'are'."
    },
    {
        question: "It ______ a cat.",
        options: ["are", "am", "is", "were"],
        answer: 2,
        explanation: "Subjek 'It' (benda/hewan tunggal) menggunakan to be 'is'."
    },
    {
        question: "You ______ very kind.",
        options: ["is", "am", "be", "are"],
        answer: 3,
        explanation: "Subjek 'You' (kamu/kalian) selalu menggunakan to be 'are', baik untuk satu orang maupun banyak."
    },

    // --- ARTICLES (A, AN) ---
    {
        question: "I have ______ apple.",
        options: ["a", "an", "the", "two"],
        answer: 1,
        explanation: "Kata 'apple' diawali dengan bunyi huruf vokal (a, i, u, e, o), jadi gunakan artikel 'an'."
    },
    {
        question: "She is ______ teacher.",
        options: ["an", "a", "these", "those"],
        answer: 1,
        explanation: "Kata 'teacher' diawali dengan bunyi huruf konsonan (t), jadi gunakan artikel 'a'."
    },
    {
        question: "It is ______ umbrella.",
        options: ["a", "an", "the", "this"],
        answer: 1,
        explanation: "Kata 'umbrella' diawali dengan bunyi vokal (u dibaca 'a'), jadi gunakan 'an'."
    },

    // --- SIMPLE PRESENT TENSE (VERBS) ---
    {
        question: "He ______ football every Sunday.",
        options: ["play", "plays", "playing", "played"],
        answer: 1,
        explanation: "Dalam Simple Present Tense, jika subjeknya 'He/She/It', kata kerja harus ditambah akhiran -s/-es ('plays')."
    },
    {
        question: "They ______ pizza.",
        options: ["likes", "like", "liking", "liked"],
        answer: 1,
        explanation: "Untuk subjek 'They/We/I/You', kata kerja tidak perlu ditambah -s ('like')."
    },
    {
        question: "My mother ______ dinner.",
        options: ["cook", "cooks", "cooking", "cooked"],
        answer: 1,
        explanation: "'My mother' sama dengan 'She' (tunggal), jadi kata kerja ditambah -s ('cooks')."
    },
    {
        question: "We ______ to school by bus.",
        options: ["go", "goes", "going", "gone"],
        answer: 0,
        explanation: "Subjek 'We' tidak memerlukan tambahan -es pada kata kerja, jadi gunakan bentuk dasar 'go'."
    },
    {
        question: "The cat ______ milk.",
        options: ["drink", "drinks", "drinking", "drank"],
        answer: 1,
        explanation: "'The cat' adalah subjek tunggal (It), jadi kata kerja ditambah -s ('drinks')."
    },
    {
        question: "I ______ English everyday.",
        options: ["studies", "study", "studying", "studied"],
        answer: 1,
        explanation: "Subjek 'I' menggunakan kata kerja bentuk dasar tanpa tambahan -s/-es ('study')."
    },

    // --- DO / DOES (QUESTIONS & NEGATIVE) ---
    {
        question: "______ you speak English?",
        options: ["Does", "Do", "Is", "Are"],
        answer: 1,
        explanation: "Untuk membuat pertanyaan dengan subjek 'You' dan kata kerja (speak), gunakan kata bantu 'Do'."
    },
    {
        question: "She ______ not like coffee.",
        options: ["do", "does", "is", "are"],
        answer: 1,
        explanation: "Untuk kalimat negatif subjek 'She', gunakan kata bantu 'does' + not."
    },
    {
        question: "______ he live here?",
        options: ["Do", "Does", "Is", "Are"],
        answer: 1,
        explanation: "Pertanyaan untuk subjek 'He' menggunakan kata bantu 'Does'."
    },
    {
        question: "We ______ not want to go.",
        options: ["does", "do", "are", "is"],
        answer: 1,
        explanation: "Kalimat negatif untuk subjek 'We' menggunakan 'do' + not."
    },

    // --- POSSESSIVE ADJECTIVES (MY, YOUR, HER, HIS) ---
    {
        question: "I have a book. This is ______ book.",
        options: ["your", "my", "his", "her"],
        answer: 1,
        explanation: "Kepemilikan untuk 'I' (saya) adalah 'my' (milikku)."
    },
    {
        question: "She is happy. ______ smile is beautiful.",
        options: ["His", "Her", "My", "Their"],
        answer: 1,
        explanation: "Kepemilikan untuk 'She' (dia perempuan) adalah 'Her' (miliknya)."
    },
    {
        question: "He drives ______ car.",
        options: ["her", "my", "his", "its"],
        answer: 2,
        explanation: "Kepemilikan untuk 'He' (dia laki-laki) adalah 'His'."
    },
    {
        question: "You must do ______ homework.",
        options: ["my", "your", "our", "their"],
        answer: 1,
        explanation: "Kepemilikan untuk 'You' adalah 'Your' (milikmu)."
    },

    // --- DEMONSTRATIVES (THIS, THAT, THESE, THOSE) ---
    {
        question: "______ is a pen (dekat).",
        options: ["This", "That", "These", "Those"],
        answer: 0,
        explanation: "'This' digunakan untuk benda tunggal yang jaraknya dekat."
    },
    {
        question: "______ are books (jauh).",
        options: ["This", "That", "These", "Those"],
        answer: 3,
        explanation: "'Those' digunakan untuk benda jamak (banyak) yang jaraknya jauh."
    },
    {
        question: "______ are my shoes (dekat).",
        options: ["That", "This", "These", "Those"],
        answer: 2,
        explanation: "'These' digunakan untuk benda jamak yang jaraknya dekat."
    },

    // --- PREPOSITIONS (IN, ON, AT) ---
    {
        question: "The book is ______ the table.",
        options: ["in", "on", "at", "to"],
        answer: 1,
        explanation: "'On' digunakan untuk benda yang berada di atas permukaan sesuatu."
    },
    {
        question: "I live ______ Jakarta.",
        options: ["on", "at", "in", "to"],
        answer: 2,
        explanation: "'In' digunakan untuk nama kota, negara, atau area yang luas."
    },
    {
        question: "I wake up ______ 6 o'clock.",
        options: ["on", "in", "at", "to"],
        answer: 2,
        explanation: "'At' digunakan untuk menunjukkan waktu jam yang spesifik."
    },
    {
        question: "My birthday is ______ January.",
        options: ["on", "in", "at", "of"],
        answer: 1,
        explanation: "'In' digunakan untuk nama bulan (tanpa tanggal spesifik)."
    },
    {
        question: "See you ______ Monday.",
        options: ["in", "at", "on", "by"],
        answer: 2,
        explanation: "'On' digunakan khusus untuk nama-nama hari."
    },

    // --- PRESENT CONTINUOUS (AM/IS/ARE + V-ING) ---
    {
        question: "I am ______ right now.",
        options: ["sleep", "sleeps", "sleeping", "slept"],
        answer: 2,
        explanation: "Setelah to be (am/is/are), jika aktivitas sedang berlangsung, gunakan Verb-ing ('sleeping')."
    },
    {
        question: "She is ______ TV.",
        options: ["watch", "watches", "watching", "watched"],
        answer: 2,
        explanation: "Kegiatan yang sedang dilakukan (is ...) memerlukan Verb-ing ('watching')."
    },
    {
        question: "They are ______ football.",
        options: ["playing", "play", "plays", "played"],
        answer: 0,
        explanation: "Pola Present Continuous: Subject + are + Verb-ing ('playing')."
    },

    // --- PRONOUNS (OBJECT) ---
    {
        question: "She loves ______ (he).",
        options: ["he", "him", "his", "himself"],
        answer: 1,
        explanation: "Jika 'he' menjadi objek (yang dikenai pekerjaan), bentuknya berubah menjadi 'him'."
    },
    {
        question: "I call ______ (they).",
        options: ["they", "their", "them", "theirs"],
        answer: 2,
        explanation: "Bentuk objek dari 'they' adalah 'them'."
    },
    {
        question: "Give the book to ______ (I).",
        options: ["I", "my", "mine", "me"],
        answer: 3,
        explanation: "Bentuk objek dari 'I' adalah 'me'."
    },

    // --- PLURAL NOUNS ---
    {
        question: "I have two ______.",
        options: ["cat", "cats", "cat's", "cates"],
        answer: 1,
        explanation: "Untuk benda lebih dari satu (two), tambahkan akhiran -s pada benda ('cats')."
    },
    {
        question: "There are three ______.",
        options: ["box", "boxs", "boxes", "boxing"],
        answer: 2,
        explanation: "Kata benda berakhiran -x jika jamak ditambah -es ('boxes')."
    },
    {
        question: "Look at those ______.",
        options: ["man", "mans", "men", "mens"],
        answer: 2,
        explanation: "'Man' adalah kata benda tak beraturan (irregular). Bentuk jamaknya adalah 'men', bukan 'mans'."
    },

    // --- MODALS (CAN) ---
    {
        question: "I ______ swim.",
        options: ["can", "cans", "canning", "to can"],
        answer: 0,
        explanation: "Modal 'can' tidak pernah berubah bentuk, apapun subjeknya."
    },
    {
        question: "He can ______ the piano.",
        options: ["play", "plays", "playing", "played"],
        answer: 0,
        explanation: "Setelah kata 'can', kata kerja harus kembali ke bentuk dasar/asli ('play') tanpa -s atau -ing."
    },

    // --- BASIC ADJECTIVES ---
    {
        question: "The elephant is ______.",
        options: ["small", "big", "long", "short"],
        answer: 1,
        explanation: "Secara logika umum, gajah itu 'big' (besar)."
    },
    {
        question: "Ice cream is ______.",
        options: ["hot", "cold", "spicy", "salty"],
        answer: 1,
        explanation: "Es krim itu sifatnya 'cold' (dingin)."
    },

    // --- WH- QUESTIONS ---
    {
        question: "______ is your name?",
        options: ["Who", "What", "Where", "When"],
        answer: 1,
        explanation: "Untuk menanyakan nama atau benda, gunakan 'What' (Apa)."
    },
    {
        question: "______ do you live?",
        options: ["What", "Who", "Where", "Why"],
        answer: 2,
        explanation: "Untuk menanyakan tempat/lokasi, gunakan 'Where' (Di mana)."
    },
    {
        question: "______ are you sad?",
        options: ["Why", "What", "Where", "Who"],
        answer: 0,
        explanation: "Untuk menanyakan alasan, gunakan 'Why' (Kenapa)."
    },

    // --- PAST SIMPLE (BASIC TO BE) ---
    {
        question: "I ______ sick yesterday.",
        options: ["am", "was", "were", "is"],
        answer: 1,
        explanation: "Kejadian lampau (yesterday) untuk subjek 'I' menggunakan to be 'was'."
    },
    {
        question: "They ______ at the park last night.",
        options: ["are", "was", "were", "is"],
        answer: 2,
        explanation: "Kejadian lampau untuk subjek jamak 'They' menggunakan to be 'were'."
    },
    {
        question: "She ______ a beautiful dress yesterday.",
        options: ["buy", "buys", "bought", "buying"],
        answer: 2,
        explanation: "Kalimat lampau (yesterday) menggunakan verb-2. Bentuk lampau dari 'buy' adalah 'bought'."
    },
    {
        question: "We ______ to Bali last year.",
        options: ["go", "goes", "went", "gone"],
        answer: 2,
        explanation: "Kata 'last year' menunjukkan masa lampau. Bentuk lampau (V2) dari 'go' adalah 'went'."
    },
    {
        question: "I ______ breakfast this morning.",
        options: ["eat", "ate", "eaten", "eating"],
        answer: 1,
        explanation: "Kejadian pagi ini (sudah lewat) pakai V2. Bentuk lampau 'eat' adalah 'ate'."
    },
    {
        question: "She ______ a letter yesterday.",
        options: ["write", "wrote", "written", "writing"],
        answer: 1,
        explanation: "Bentuk lampau (V2) dari 'write' adalah 'wrote'."
    },
    {
        question: "They ______ football two days ago.",
        options: ["play", "played", "playing", "plays"],
        answer: 1,
        explanation: "Kata kerja beraturan (regular verb) untuk masa lampau tinggal ditambah akhiran -ed ('played')."
    },
    {
        question: "He ______ not come to the party last night.",
        options: ["do", "does", "did", "is"],
        answer: 2,
        explanation: "Untuk kalimat negatif di masa lampau (past tense), gunakan kata bantu 'did' + not."
    },

    // --- FUTURE TENSE (WILL) ---
    {
        question: "I ______ call you later.",
        options: ["will", "am", "did", "does"],
        answer: 0,
        explanation: "Untuk menyatakan kejadian di masa depan (nanti), gunakan 'will'."
    },
    {
        question: "She ______ go to school tomorrow.",
        options: ["will", "wills", "willing", "to will"],
        answer: 0,
        explanation: "Modal 'will' tidak berubah bentuk meskipun subjeknya 'She'."
    },
    {
        question: "They will ______ here soon.",
        options: ["arrived", "arrives", "arrive", "arriving"],
        answer: 2,
        explanation: "Setelah kata 'will', kata kerja harus kembali ke bentuk dasar/asli ('arrive')."
    },

    // --- COMPARATIVE & SUPERLATIVE (PERBANDINGAN) ---
    {
        question: "An elephant is ______ than a mouse.",
        options: ["big", "bigger", "biggest", "more big"],
        answer: 1,
        explanation: "Jika membandingkan 2 benda (lebih besar), tambahkan -er ('bigger') dan diikuti 'than'."
    },
    {
        question: "The giraffe is the ______ animal.",
        options: ["tall", "taller", "tallest", "most tall"],
        answer: 2,
        explanation: "Jika menyatakan 'paling' (superlative), gunakan 'the' + akhiran -est ('tallest')."
    },
    {
        question: "My car is ______ than yours.",
        options: ["fast", "faster", "fastest", "fastly"],
        answer: 1,
        explanation: "Perbandingan 'lebih cepat' menggunakan akhiran -er ('faster')."
    },
    {
        question: "This test is ______ than the last one.",
        options: ["hard", "harder", "hardest", "hardly"],
        answer: 1,
        explanation: "Lebih susah = 'harder'."
    },
    {
        question: "Today is the ______ day of my life.",
        options: ["good", "better", "best", "goodest"],
        answer: 2,
        explanation: "Bentuk paling (superlative) dari 'good' adalah 'best' (terbaik), bukan 'goodest'."
    },

    // --- QUANTIFIERS (MUCH, MANY, SOME, ANY) ---
    {
        question: "How ______ money do you have?",
        options: ["many", "much", "some", "any"],
        answer: 1,
        explanation: "Uang (money) dianggap benda tak bisa dihitung satu-satu (uncountable), jadi pakai 'much'."
    },
    {
        question: "How ______ books are on the table?",
        options: ["much", "many", "any", "little"],
        answer: 1,
        explanation: "Buku (books) bisa dihitung jari (countable), jadi pakai 'many'."
    },
    {
        question: "I have ______ friends.",
        options: ["some", "any", "much", "little"],
        answer: 0,
        explanation: "Untuk kalimat positif, gunakan 'some' (beberapa)."
    },
    {
        question: "I don't have ______ water.",
        options: ["some", "any", "many", "a"],
        answer: 1,
        explanation: "Untuk kalimat negatif (don't), gunakan 'any' (tidak ada sama sekali)."
    },
    {
        question: "Do you have ______ brothers?",
        options: ["some", "any", "much", "little"],
        answer: 1,
        explanation: "Untuk kalimat tanya (question), biasanya menggunakan 'any'."
    },

    // --- CONJUNCTIONS (KATA HUBUNG) ---
    {
        question: "I like coffee ______ tea.",
        options: ["but", "or", "and", "so"],
        answer: 2,
        explanation: "'And' digunakan untuk menggabungkan dua hal yang setara/positif."
    },
    {
        question: "I want to buy a car, ______ I have no money.",
        options: ["and", "because", "but", "so"],
        answer: 2,
        explanation: "'But' (tapi) digunakan untuk hal yang bertentangan."
    },
    {
        question: "He is happy ______ he passed the exam.",
        options: ["so", "but", "because", "and"],
        answer: 2,
        explanation: "'Because' (karena) digunakan untuk menjelaskan alasan."
    },

    // --- ADVERBS OF FREQUENCY (SEBERAPA SERING) ---
    {
        question: "I ______ wake up at 6 AM. (Setiap hari)",
        options: ["never", "sometimes", "always", "rarely"],
        answer: 2,
        explanation: "'Always' artinya selalu (setiap saat)."
    },
    {
        question: "She ______ eats meat. She is a vegetarian.",
        options: ["always", "never", "often", "usually"],
        answer: 1,
        explanation: "Vegetarian tidak makan daging, jadi jawabannya 'never' (tidak pernah)."
    },

    // --- FAMILY VOCABULARY ---
    {
        question: "My father's brother is my ______.",
        options: ["aunt", "uncle", "cousin", "grandfather"],
        answer: 1,
        explanation: "Saudara laki-laki dari ayah disebut 'uncle' (paman)."
    },
    {
        question: "My mother's mother is my ______.",
        options: ["grandmother", "grandfather", "aunt", "sister"],
        answer: 0,
        explanation: "Ibu dari ibu kita disebut 'grandmother' (nenek)."
    },
    {
        question: "My aunt's child is my ______.",
        options: ["brother", "sister", "cousin", "nephew"],
        answer: 2,
        explanation: "Anak dari bibi/paman disebut 'cousin' (sepupu)."
    },

    // --- DAYS & MONTHS ---
    {
        question: "The day after Monday is ______.",
        options: ["Sunday", "Tuesday", "Wednesday", "Friday"],
        answer: 1,
        explanation: "Hari setelah Senin (Monday) adalah Selasa (Tuesday)."
    },
    {
        question: "The month before February is ______.",
        options: ["January", "March", "December", "April"],
        answer: 0,
        explanation: "Bulan sebelum Februari adalah Januari."
    },

    // --- TELLING TIME ---
    {
        question: "It is 07:30. It is half ______ seven.",
        options: ["to", "past", "clock", "on"],
        answer: 1,
        explanation: "Lewat 30 menit disebut 'half past'."
    },
    {
        question: "It is 09:00. It is nine o'______.",
        options: ["clock", "watch", "time", "hour"],
        answer: 0,
        explanation: "Untuk jam tepat, gunakan 'o'clock'."
    },

    // --- POSSESSIVE ('S) ---
    {
        question: "This is ______ car. (Milik John)",
        options: ["John", "Johns", "John's", "John is"],
        answer: 2,
        explanation: "Untuk menyatakan kepemilikan nama orang, tambahkan 's (apostrof s)."
    },

    // --- IMPERATIVE (KALIMAT PERINTAH) ---
    {
        question: "______ the door, please.",
        options: ["Opens", "Opening", "Open", "Opened"],
        answer: 2,
        explanation: "Kalimat perintah selalu diawali kata kerja bentuk dasar ('Open')."
    },
    {
        question: "______ be late!",
        options: ["Doesn't", "Don't", "Not", "No"],
        answer: 1,
        explanation: "Larangan (Jangan) menggunakan kata 'Don't'."
    },
    {
        question: "______ quiet, please.",
        options: ["Is", "Be", "Are", "Do"],
        answer: 1,
        explanation: "Jika memerintah seseorang untuk bersikap (kata sifat), gunakan 'Be'."
    },

    // --- GENERAL VOCABULARY & GRAMMAR MIX ---
    {
        question: "I use a ______ to write.",
        options: ["spoon", "pen", "shoe", "car"],
        answer: 1,
        explanation: "Benda untuk menulis adalah 'pen' (pena)."
    },
    {
        question: "We eat with a ______.",
        options: ["spoon", "bed", "lamp", "soap"],
        answer: 0,
        explanation: "Kita makan menggunakan 'spoon' (sendok)."
    },
    {
        question: "______ color is the sky?",
        options: ["Who", "What", "When", "Where"],
        answer: 1,
        explanation: "Menanyakan warna benda menggunakan 'What'."
    },
    {
        question: "The sky is ______.",
        options: ["green", "blue", "yellow", "red"],
        answer: 1,
        explanation: "Warna langit adalah 'blue' (biru)."
    },
    {
        question: "Apples are usually ______.",
        options: ["blue", "purple", "red", "black"],
        answer: 2,
        explanation: "Apel biasanya berwarna 'red' (merah)."
    },
    {
        question: "My father works in a hospital. He is a ______.",
        options: ["teacher", "doctor", "farmer", "driver"],
        answer: 1,
        explanation: "Orang yang bekerja di rumah sakit biasanya 'doctor' (dokter)."
    },
    {
        question: "She teaches students. She is a ______.",
        options: ["doctor", "teacher", "pilot", "police"],
        answer: 1,
        explanation: "Orang yang mengajar murid adalah 'teacher' (guru)."
    },
    {
        question: "Can I ______ some water?",
        options: ["have", "has", "having", "had"],
        answer: 0,
        explanation: "Setelah 'Can I', gunakan kata kerja dasar 'have'."
    },
    {
        question: "______ old are you?",
        options: ["Who", "What", "How", "Where"],
        answer: 2,
        explanation: "Menanyakan umur menggunakan 'How old'."
    },
    {
        question: "I am hungry. I want to ______.",
        options: ["sleep", "eat", "run", "read"],
        answer: 1,
        explanation: "Jika lapar (hungry), maka ingin makan (eat)."
    },
    {
        question: "I am thirsty. I want to ______.",
        options: ["eat", "drink", "walk", "study"],
        answer: 1,
        explanation: "Jika haus (thirsty), maka ingin minum (drink)."
    },
    {
        question: "They ______ students.",
        options: ["is", "am", "are", "be"],
        answer: 2,
        explanation: "Subjek 'They' pasangannya 'are'."
    },
    {
        question: "She ______ beautiful.",
        options: ["looks", "look", "looking", "to look"],
        answer: 0,
        explanation: "Subjek tunggal 'She' + Verb (look) harus ditambah -s ('looks')."
    },
    {
        question: "Do you ______ music?",
        options: ["likes", "like", "liking", "to like"],
        answer: 1,
        explanation: "Setelah 'Do you', kata kerja kembali ke dasar 'like'."
    },
    {
        question: "My brother ______ video games.",
        options: ["play", "plays", "playing", "played"],
        answer: 1,
        explanation: "Saudara laki-laki (He) + kata kerja harus ditambah -s ('plays')."
    },
    {
        question: "Where ______ you going?",
        options: ["is", "am", "are", "do"],
        answer: 2,
        explanation: "Pasangan 'You' dalam kalimat tanya continuous adalah 'Are'."
    },
    {
        question: "Is this ______ book?",
        options: ["you", "yours", "your", "mine"],
        answer: 2,
        explanation: "Diikuti benda (book), maka gunakan kepemilikan 'your'."
    },
    {
        question: "No, that is ______ (milik saya).",
        options: ["my", "mine", "me", "I"],
        answer: 1,
        explanation: "Jika tidak diikuti benda di belakangnya, gunakan 'mine' (milikku)."
    },
    {
        question: "______ is a book on the table.",
        options: ["There", "Their", "They", "These"],
        answer: 0,
        explanation: "'There is' digunakan untuk menyatakan 'ada' (benda tunggal)."
    },
    {
        question: "There ______ five apples in the basket.",
        options: ["is", "am", "are", "be"],
        answer: 2,
        explanation: "Karena bendanya banyak (five apples), gunakan 'There are'."
    },
    {
        question: "______ there any milk in the fridge?",
        options: ["Are", "Is", "Am", "Do"],
        answer: 1,
        explanation: "Susu (milk) adalah benda cair (uncountable/tak bisa dihitung), dianggap tunggal. Gunakan 'Is'."
    },
    {
        question: "There are many ______ in the classroom.",
        options: ["student", "students", "student's", "studying"],
        answer: 1,
        explanation: "Setelah 'There are many', kata benda harus dalam bentuk jamak (tambah -s)."
    },
    {
        question: "Is there a cat here? Yes, there ______.",
        options: ["are", "is", "do", "does"],
        answer: 1,
        explanation: "Jawaban pendek mengikuti pertanyaannya. Jika tanya 'Is there', jawab 'Yes, there is'."
    },

    // --- HAVE / HAS (MEMPUNYAI) ---
    {
        question: "I ______ a new bicycle.",
        options: ["has", "have", "having", "had"],
        answer: 1,
        explanation: "Subjek 'I' (saya) menggunakan 'have' untuk menyatakan kepemilikan."
    },
    {
        question: "She ______ long hair.",
        options: ["have", "has", "having", "haves"],
        answer: 1,
        explanation: "Subjek 'She/He/It' menggunakan 'has'."
    },
    {
        question: "They ______ a big house.",
        options: ["has", "have", "having", "had"],
        answer: 1,
        explanation: "Subjek 'They' (mereka) menggunakan 'have'."
    },
    {
        question: "Do you ______ a pen?",
        options: ["have", "has", "had", "haves"],
        answer: 0,
        explanation: "Setelah 'Do you', kata kerja kembali ke bentuk dasar 'have'."
    },
    {
        question: "He doesn't ______ any money.",
        options: ["has", "have", "had", "having"],
        answer: 1,
        explanation: "Setelah 'doesn't', kata kerja harus kembali ke bentuk dasar 'have' (bukan has)."
    },

    // --- LIKE + V-ING (HOBBY/KESUKAAN) ---
    {
        question: "I like ______ football.",
        options: ["play", "playing", "plays", "played"],
        answer: 1,
        explanation: "Setelah kata 'like' untuk hobi, kata kerjanya biasanya ditambah -ing (Gerund)."
    },
    {
        question: "She loves ______ books.",
        options: ["read", "reads", "reading", "reader"],
        answer: 2,
        explanation: "Sama seperti 'like', setelah 'loves' gunakan V-ing ('reading')."
    },
    {
        question: "We enjoy ______ movies.",
        options: ["watch", "watching", "watches", "watched"],
        answer: 1,
        explanation: "Kata 'enjoy' (menikmati) selalu diikuti V-ing ('watching')."
    },
    {
        question: "He hates ______ up early.",
        options: ["get", "gets", "getting", "got"],
        answer: 2,
        explanation: "Setelah 'hates' (benci), gunakan V-ing ('getting')."
    },
    {
        question: "Stop ______!",
        options: ["talk", "talks", "talking", "talked"],
        answer: 2,
        explanation: "Kata perintah 'Stop' diikuti kegiatan yang sedang dilakukan (V-ing)."
    },

    // --- ADVERBS OF MANNER (CARA MELAKUKAN SESUATU) ---
    {
        question: "He runs very ______.",
        options: ["quick", "quickly", "quicker", "quickest"],
        answer: 1,
        explanation: "Untuk menjelaskan cara lari (kata kerja), gunakan akhiran -ly ('quickly' = dengan cepat)."
    },
    {
        question: "She sings ______.",
        options: ["beautiful", "beautifully", "beauty", "beauties"],
        answer: 1,
        explanation: "Menjelaskan cara menyanyi (verb), gunakan 'beautifully' (dengan indah)."
    },
    {
        question: "Please speak ______.",
        options: ["slow", "slowly", "slower", "slows"],
        answer: 1,
        explanation: "Berbicaralah 'dengan pelan' (slowly)."
    },
    {
        question: "They study ______.",
        options: ["hard", "hardly", "harder", "hardest"],
        answer: 0,
        explanation: "Pengecualian! 'Hard' (giat/keras) tidak ditambah -ly. 'Hardly' artinya 'hampir tidak'."
    },
    {
        question: "He drives ______.",
        options: ["careful", "carefully", "care", "caring"],
        answer: 1,
        explanation: "Mengemudi 'dengan hati-hati' adalah 'carefully'."
    },

    // --- PREPOSITIONS OF PLACE (LANJUTAN) ---
    {
        question: "The cat is ______ the table (di bawah).",
        options: ["on", "in", "under", "above"],
        answer: 2,
        explanation: "'Under' artinya di bawah."
    },
    {
        question: "I am standing ______ you and him (di antara).",
        options: ["between", "among", "in", "on"],
        answer: 0,
        explanation: "'Between' digunakan jika berada di antara dua orang/benda."
    },
    {
        question: "The car is in ______ of the house (di depan).",
        options: ["back", "front", "side", "middle"],
        answer: 1,
        explanation: "Frasa yang benar adalah 'in front of' (di depan)."
    },
    {
        question: "Who is sitting ______ you? (di belakang)",
        options: ["behind", "front", "next", "under"],
        answer: 0,
        explanation: "'Behind' artinya di belakang."
    },
    {
        question: "Sit ______ to me. (di sebelah)",
        options: ["near", "next", "beside", "close"],
        answer: 1,
        explanation: "Frasa 'next to' artinya di sebelah."
    },

    // --- SHORT ANSWERS (JAWABAN PENDEK) ---
    {
        question: "Do you like pizza? Yes, I ______.",
        options: ["like", "am", "do", "will"],
        answer: 2,
        explanation: "Jika pertanyaan dimulai dengan 'Do', jawaban pendeknya 'Yes, I do'."
    },
    {
        question: "Is she a doctor? No, she ______.",
        options: ["doesn't", "isn't", "aren't", "don't"],
        answer: 1,
        explanation: "Pertanyaan 'Is she...?' dijawab dengan to be 'isn't' (is not)."
    },
    {
        question: "Can you swim? Yes, I ______.",
        options: ["can", "do", "am", "will"],
        answer: 0,
        explanation: "Pertanyaan 'Can' dijawab dengan 'can'."
    },
    {
        question: "Are they happy? Yes, they ______.",
        options: ["is", "do", "are", "were"],
        answer: 2,
        explanation: "Pertanyaan 'Are they...?' dijawab dengan 'are'."
    },
    {
        question: "Did you go? No, I ______.",
        options: ["didn't", "don't", "wasn't", "not"],
        answer: 0,
        explanation: "Pertanyaan lampau 'Did' dijawab negatif dengan 'didn't'."
    },

    // --- FEELINGS & EMOTIONS (PERASAAN) ---
    {
        question: "I want to sleep. I am ______.",
        options: ["hungry", "thirsty", "tired", "happy"],
        answer: 2,
        explanation: "Ingin tidur berarti merasa 'tired' (lelah)."
    },
    {
        question: "She is crying. She is ______.",
        options: ["sad", "happy", "funny", "excited"],
        answer: 0,
        explanation: "Menangis biasanya karena 'sad' (sedih)."
    },
    {
        question: "The ghost movie is scary. I am ______.",
        options: ["afraid", "brave", "happy", "angry"],
        answer: 0,
        explanation: "Jika film seram, kita merasa 'afraid' (takut)."
    },
    {
        question: "I have no food. I am ______.",
        options: ["angry", "hungry", "thirsty", "full"],
        answer: 1,
        explanation: "Tidak ada makanan berarti 'hungry' (lapar)."
    },
    {
        question: "He is smiling. He is ______.",
        options: ["sad", "angry", "happy", "sick"],
        answer: 2,
        explanation: "Tersenyum tandanya 'happy' (senang)."
    },

    // --- CLOTHES (PAKAIAN) ---
    {
        question: "I wear ______ on my feet.",
        options: ["hat", "shoes", "gloves", "shirt"],
        answer: 1,
        explanation: "Yang dipakai di kaki adalah 'shoes' (sepatu)."
    },
    {
        question: "When it is cold, I wear a ______.",
        options: ["jacket", "t-shirt", "shorts", "sandal"],
        answer: 0,
        explanation: "Saat dingin kita memakai 'jacket' (jaket)."
    },
    {
        question: "He wears a ______ on his head.",
        options: ["shoe", "belt", "hat", "sock"],
        answer: 2,
        explanation: "Yang dipakai di kepala adalah 'hat' (topi)."
    },
    {
        question: "Men usually wear ______ to work.",
        options: ["skirt", "dress", "trousers", "blouse"],
        answer: 2,
        explanation: "Laki-laki biasanya memakai 'trousers' (celana panjang)."
    },
    {
        question: "I need a ______ to hold up my pants.",
        options: ["tie", "belt", "scarf", "ring"],
        answer: 1,
        explanation: "Benda untuk menahan celana adalah 'belt' (ikat pinggang)."
    },

    // --- WEATHER (CUACA) ---
    {
        question: "It is raining. Bring an ______.",
        options: ["umbrella", "sunglasses", "hat", "cream"],
        answer: 0,
        explanation: "Saat hujan, bawalah 'umbrella' (payung)."
    },
    {
        question: "The sun is hot. It is ______.",
        options: ["rainy", "snowy", "sunny", "cloudy"],
        answer: 2,
        explanation: "Matahari panas berarti cuaca 'sunny' (cerah/panas)."
    },
    {
        question: "It is cold and white. It is ______.",
        options: ["raining", "snowing", "burning", "drying"],
        answer: 1,
        explanation: "Dingin dan putih identik dengan 'snowing' (bersalju)."
    },

    // --- BODY PARTS (ANGGOTA TUBUH) ---
    {
        question: "I see with my ______.",
        options: ["ears", "nose", "eyes", "hands"],
        answer: 2,
        explanation: "Kita melihat dengan 'eyes' (mata)."
    },
    {
        question: "I hear with my ______.",
        options: ["eyes", "mouth", "ears", "nose"],
        answer: 2,
        explanation: "Kita mendengar dengan 'ears' (telinga)."
    },
    {
        question: "I walk with my ______.",
        options: ["hands", "legs", "arms", "head"],
        answer: 1,
        explanation: "Kita berjalan dengan 'legs' (kaki)."
    },
    {
        question: "I have ten ______ on my hands.",
        options: ["toes", "fingers", "knees", "elbows"],
        answer: 1,
        explanation: "Jari tangan disebut 'fingers'."
    },
    {
        question: "My head hurts. I have a ______.",
        options: ["headache", "stomachache", "backache", "toothache"],
        answer: 0,
        explanation: "Sakit kepala disebut 'headache'."
    },

    // --- MIXED GRAMMAR (CAMPURAN) ---
    {
        question: "______ car is this?",
        options: ["Who", "Whose", "Who's", "Whom"],
        answer: 1,
        explanation: "Menanyakan kepemilikan (Punya siapa) menggunakan 'Whose'."
    },
    {
        question: "I am smarter ______ him.",
        options: ["then", "than", "that", "there"],
        answer: 1,
        explanation: "Untuk membandingkan (daripada), gunakan 'than' (dengan huruf a)."
    },
    {
        question: "Please look ______ the whiteboard.",
        options: ["at", "in", "on", "to"],
        answer: 0,
        explanation: "Pasangan kata kerja look adalah 'at' (look at = melihat ke)."
    },
    {
        question: "I am listening ______ music.",
        options: ["at", "in", "to", "on"],
        answer: 2,
        explanation: "Pasangan kata listen adalah 'to' (listen to = mendengarkan)."
    },
    {
        question: "Wait ______ me!",
        options: ["to", "for", "at", "in"],
        answer: 1,
        explanation: "Menunggu seseorang menggunakan 'wait for'."
    },
    {
        question: "You are sick. You ______ go to the doctor.",
        options: ["should", "will", "can", "may"],
        answer: 0,
        explanation: "'Should' digunakan untuk memberikan saran (sebaiknya)."
    },
    {
        question: "The traffic light is red. You ______ stop.",
        options: ["can", "should", "must", "may"],
        answer: 2,
        explanation: "'Must' digunakan untuk aturan wajib/keharusan. Lampu merah wajib berhenti."
    },
    {
        question: "It is raining outside. You ______ take an umbrella.",
        options: ["must", "should", "can", "will"],
        answer: 1,
        explanation: "Ini adalah saran, jadi lebih tepat menggunakan 'should'."
    },
    {
        question: "Students ______ wear a uniform at school.",
        options: ["can", "may", "must", "should"],
        answer: 2,
        explanation: "Memakai seragam adalah peraturan sekolah (wajib), jadi gunakan 'must'."
    },
    {
        question: "You ______ eat too much candy. It is bad for your teeth.",
        options: ["shouldn't", "mustn't", "don't", "won't"],
        answer: 0,
        explanation: "Saran untuk *tidak* melakukan sesuatu menggunakan 'should not' (shouldn't)."
    },

    // --- DAILY ROUTINES (KEGIATAN SEHARI-HARI) ---
    {
        question: "I ______ up at 5 o'clock every morning.",
        options: ["stand", "get", "go", "make"],
        answer: 1,
        explanation: "Frasa yang benar untuk bangun tidur adalah 'get up'."
    },
    {
        question: "I ______ my teeth after eating.",
        options: ["wash", "brush", "clean", "scrub"],
        answer: 1,
        explanation: "Menggosok gigi menggunakan kata kerja 'brush'."
    },
    {
        question: "She ______ a shower in the morning.",
        options: ["takes", "has", "does", "makes"],
        answer: 0,
        explanation: "Mandi bisa menggunakan 'take a shower'. Karena subjek 'She', menjadi 'takes'."
    },
    {
        question: "We ______ breakfast together.",
        options: ["eat", "drink", "do", "play"],
        answer: 0,
        explanation: "Sarapan adalah kegiatan makan, jadi 'eat breakfast' (atau 'have breakfast')."
    },
    {
        question: "He ______ to bed at 10 PM.",
        options: ["sleeps", "goes", "runs", "walks"],
        answer: 1,
        explanation: "Pergi tidur frasanya adalah 'go to bed'. Subjek He = 'goes'."
    },

    // --- ROOMS IN THE HOUSE (RUANGAN) ---
    {
        question: "I sleep in the ______.",
        options: ["bathroom", "kitchen", "bedroom", "garage"],
        answer: 2,
        explanation: "Tempat tidur ada di 'bedroom' (kamar tidur)."
    },
    {
        question: "My mother cooks in the ______.",
        options: ["bedroom", "living room", "kitchen", "garden"],
        answer: 2,
        explanation: "Memasak dilakukan di 'kitchen' (dapur)."
    },
    {
        question: "We watch TV in the ______.",
        options: ["bathroom", "living room", "garage", "dining room"],
        answer: 1,
        explanation: "Nonton TV biasanya di 'living room' (ruang tamu/keluarga)."
    },
    {
        question: "I take a bath in the ______.",
        options: ["bathroom", "bedroom", "kitchen", "hall"],
        answer: 0,
        explanation: "Mandi dilakukan di 'bathroom' (kamar mandi)."
    },
    {
        question: "We eat dinner in the ______.",
        options: ["bedroom", "bathroom", "dining room", "garden"],
        answer: 2,
        explanation: "Makan malam dilakukan di 'dining room' (ruang makan)."
    },

    // --- QUESTION TAGS (MENGKONFIRMASI) ---
    {
        question: "You are a student, ______?",
        options: ["aren't you", "don't you", "isn't it", "do you"],
        answer: 0,
        explanation: "Jika kalimat positif pakai 'are', question tag-nya negatif 'aren't you?'."
    },
    {
        question: "She is beautiful, ______?",
        options: ["is she", "isn't she", "does she", "didn't she"],
        answer: 1,
        explanation: "Kalimat positif 'is', tag-nya negatif 'isn't she?'."
    },
    {
        question: "He can swim, ______?",
        options: ["can he", "can't he", "does he", "is he"],
        answer: 1,
        explanation: "Modal 'can' positif, tag-nya negatif 'can't he?'."
    },
    {
        question: "They aren't here, ______?",
        options: ["are they", "aren't they", "do they", "don't they"],
        answer: 0,
        explanation: "Jika kalimat awalnya negatif (aren't), tag-nya positif 'are they?'."
    },
    {
        question: "It is a cat, ______?",
        options: ["is it", "isn't it", "does it", "don't it"],
        answer: 1,
        explanation: "Subjek 'It is', tag-nya 'isn't it?'."
    },

    // --- CONJUNCTIONS (KATA HUBUNG WAKTU/SYARAT) ---
    {
        question: "I will call you ______ I arrive.",
        options: ["so", "but", "when", "or"],
        answer: 2,
        explanation: "'When' (ketika) digunakan untuk menghubungkan waktu kejadian."
    },
    {
        question: "If it rains, I ______ stay at home.",
        options: ["will", "do", "am", "have"],
        answer: 0,
        explanation: "Kalimat pengandaian (Conditional Type 1): If + Present, Subject + Will."
    },
    {
        question: "I study hard ______ pass the exam.",
        options: ["to", "for", "so", "but"],
        answer: 0,
        explanation: "'To' di sini berarti 'untuk/supaya' (diikuti kata kerja)."
    },

    // --- TRANSPORTATION (TRANSPORTASI) ---
    {
        question: "I go to school ______ bus.",
        options: ["in", "on", "by", "with"],
        answer: 2,
        explanation: "Untuk alat transportasi umum, gunakan preposisi 'by' (by bus, by car, by plane)."
    },
    {
        question: "He goes to work ______ foot (jalan kaki).",
        options: ["by", "on", "in", "with"],
        answer: 1,
        explanation: "Pengecualian: Jalan kaki selalu menggunakan 'on foot', bukan 'by foot'."
    },
    {
        question: "The plane flies in the ______.",
        options: ["sea", "sky", "road", "ground"],
        answer: 1,
        explanation: "Pesawat terbang di 'sky' (langit)."
    },
    {
        question: "The ship sails on the ______.",
        options: ["sky", "sea", "air", "land"],
        answer: 1,
        explanation: "Kapal berlayar di 'sea' (laut)."
    },

    // --- OBJECT PRONOUNS (KATA GANTI OBJEK) ---
    {
        question: "I don't know ______ (dia laki-laki).",
        options: ["he", "his", "him", "himself"],
        answer: 2,
        explanation: "Sebagai objek, 'He' berubah menjadi 'Him'."
    },
    {
        question: "Please help ______ (kami).",
        options: ["we", "us", "our", "ours"],
        answer: 1,
        explanation: "Sebagai objek, 'We' berubah menjadi 'Us'."
    },
    {
        question: "Do you like ______ (itu/benda)?",
        options: ["it", "its", "they", "them"],
        answer: 0,
        explanation: "Benda tunggal sebagai objek tetap 'it'."
    },

    // --- COMMON VERBS & PHRASAL VERBS ---
    {
        question: "Please ______ on the light. It's dark.",
        options: ["turn", "get", "make", "do"],
        answer: 0,
        explanation: "Menyalakan lampu adalah 'turn on'."
    },
    {
        question: "Please ______ off the TV before sleeping.",
        options: ["turn", "go", "put", "set"],
        answer: 0,
        explanation: "Mematikan alat elektronik adalah 'turn off'."
    },
    {
        question: "______ down, please.",
        options: ["Sit", "Stand", "Run", "Walk"],
        answer: 0,
        explanation: "Duduklah = 'Sit down'."
    },
    {
        question: "______ up, please.",
        options: ["Sit", "Stand", "Lie", "Sleep"],
        answer: 1,
        explanation: "Berdirilah = 'Stand up'."
    },
    {
        question: "Can I ______ on this shirt?",
        options: ["try", "do", "make", "get"],
        answer: 0,
        explanation: "Mencoba pakaian = 'try on'."
    },

    // --- VOCABULARY: ANIMALS ---
    {
        question: "A ______ has a very long neck.",
        options: ["lion", "elephant", "giraffe", "monkey"],
        answer: 2,
        explanation: "Hewan berleher panjang adalah 'giraffe' (jerapah)."
    },
    {
        question: "A ______ can fly.",
        options: ["dog", "bird", "fish", "cat"],
        answer: 1,
        explanation: "Hewan yang bisa terbang adalah 'bird' (burung)."
    },
    {
        question: "A ______ lives in the water.",
        options: ["bird", "fish", "cat", "cow"],
        answer: 1,
        explanation: "Hewan yang hidup di air adalah 'fish' (ikan)."
    },
    {
        question: "A ______ produces milk.",
        options: ["chicken", "cow", "snake", "fish"],
        answer: 1,
        explanation: "Hewan penghasil susu adalah 'cow' (sapi)."
    },
    {
        question: "A ______ likes bananas.",
        options: ["lion", "cat", "monkey", "dog"],
        answer: 2,
        explanation: "Hewan yang identik suka pisang adalah 'monkey' (monyet)."
    },

    // --- SPELLING & ARTICLES TRICK ---
    {
        question: "I wait for ______ hour.",
        options: ["a", "an", "the", "this"],
        answer: 1,
        explanation: "Kata 'hour' (jam) dibaca dengan bunyi vokal 'our' (h tidak dibaca), jadi pakai 'an'."
    },
    {
        question: "She is ______ university student.",
        options: ["a", "an", "the", "those"],
        answer: 0,
        explanation: "Kata 'university' dibaca dengan bunyi 'yu' (konsonan Y), jadi pakai 'a', bukan 'an'."
    },

    // --- TIME EXPRESSIONS (KETERANGAN WAKTU) ---
    {
        question: "I saw him two days ______.",
        options: ["ago", "last", "next", "before"],
        answer: 0,
        explanation: "Untuk menyatakan rentang waktu yang sudah lewat (yg lalu), gunakan 'ago' di belakang (two days ago)."
    },
    {
        question: "I will go to Bali ______ week.",
        options: ["ago", "last", "next", "yesterday"],
        answer: 2,
        explanation: "Minggu depan = 'next week'."
    },
    {
        question: "Where were you ______ night?",
        options: ["ago", "last", "next", "tomorrow"],
        answer: 1,
        explanation: "Tadi malam = 'last night'."
    },

    // --- QUANTITY (SEDIKIT/BANYAK) ---
    {
        question: "There is a ______ water in the glass.",
        options: ["few", "little", "many", "several"],
        answer: 1,
        explanation: "Air (uncountable) jika sedikit menggunakan 'little'. 'Few' untuk benda yang bisa dihitung."
    },
    {
        question: "I have a ______ friends.",
        options: ["little", "much", "few", "any"],
        answer: 2,
        explanation: "Teman (countable/bisa dihitung) jika sedikit menggunakan 'few'."
    },
    {
        question: "A ______ flies an airplane.",
        options: ["driver", "pilot", "doctor", "farmer"],
        answer: 1,
        explanation: "Orang yang menerbangkan pesawat adalah 'pilot'."
    },
    {
        question: "A ______ cooks food in a restaurant.",
        options: ["chef", "police", "nurse", "teacher"],
        answer: 0,
        explanation: "Orang yang memasak di restoran disebut 'chef' (koki)."
    },
    {
        question: "A ______ catches thieves.",
        options: ["postman", "police officer", "firefighter", "singer"],
        answer: 1,
        explanation: "Orang yang menangkap pencuri adalah 'police officer' (polisi)."
    },
    {
        question: "A ______ puts out fires.",
        options: ["firefighter", "driver", "dentist", "artist"],
        answer: 0,
        explanation: "Orang yang memadamkan api adalah 'firefighter' (pemadam kebakaran)."
    },
    {
        question: "A ______ fixes teeth.",
        options: ["doctor", "dentist", "nurse", "soldier"],
        answer: 1,
        explanation: "Dokter yang khusus menangani gigi adalah 'dentist'."
    },

    // --- OPPOSITES (LAWAN KATA) ---
    {
        question: "Fire is hot. Ice is ______.",
        options: ["warm", "cold", "hard", "soft"],
        answer: 1,
        explanation: "Lawan kata panas (hot) adalah dingin (cold)."
    },
    {
        question: "An elephant is big. A mouse is ______.",
        options: ["huge", "small", "tall", "fat"],
        answer: 1,
        explanation: "Lawan kata besar (big) adalah kecil (small)."
    },
    {
        question: "The rock is hard. The pillow is ______.",
        options: ["soft", "strong", "heavy", "light"],
        answer: 0,
        explanation: "Lawan kata keras (hard) untuk benda adalah empuk/lunak (soft)."
    },
    {
        question: "The turtle is slow. The rabbit is ______.",
        options: ["lazy", "fast", "weak", "sad"],
        answer: 1,
        explanation: "Lawan kata lambat (slow) adalah cepat (fast)."
    },
    {
        question: "I am happy. I am not ______.",
        options: ["sad", "glad", "excited", "good"],
        answer: 0,
        explanation: "Lawan kata senang (happy) adalah sedih (sad)."
    },

    // --- IRREGULAR PLURALS (JAMAK TAK BERATURAN) ---
    {
        question: "I have one child. They have three ______.",
        options: ["childs", "child", "children", "childrens"],
        answer: 2,
        explanation: "Bentuk jamak dari 'child' adalah 'children' (tanpa s)."
    },
    {
        question: "Look at those ______ (tikus-tikus)!",
        options: ["mouse", "mouses", "mice", "mices"],
        answer: 2,
        explanation: "Bentuk jamak dari 'mouse' adalah 'mice'."
    },
    {
        question: "Brush your ______ (gigi-gigi) every day.",
        options: ["tooth", "teeth", "tooths", "teeths"],
        answer: 1,
        explanation: "Bentuk jamak dari 'tooth' adalah 'teeth'."
    },
    {
        question: "There are two ______ (wanita) in the room.",
        options: ["woman", "womans", "women", "womens"],
        answer: 2,
        explanation: "Bentuk jamak dari 'woman' (dibaca: wimin) adalah 'women'."
    },
    {
        question: "My feet ______ (kaki) are tired.",
        options: ["foot", "feet", "foots", "feets"],
        answer: 1,
        explanation: "Bentuk jamak dari 'foot' adalah 'feet'."
    },

    // --- BASIC MATH & NUMBERS (ANGKA) ---
    {
        question: "Five plus five is ______.",
        options: ["eight", "nine", "ten", "eleven"],
        answer: 2,
        explanation: "5 + 5 = 10 (ten)."
    },
    {
        question: "Twenty minus five is ______.",
        options: ["fifty", "fifteen", "twelve", "five"],
        answer: 1,
        explanation: "20 - 5 = 15 (fifteen)."
    },
    {
        question: "The first month of the year is ______.",
        options: ["February", "January", "March", "December"],
        answer: 1,
        explanation: "Bulan pertama (first) adalah Januari."
    },
    {
        question: "The number after nineteen is ______.",
        options: ["eighteen", "twenty", "twenty-one", "ninety"],
        answer: 1,
        explanation: "Angka setelah 19 (nineteen) adalah 20 (twenty)."
    },
    {
        question: "One hundred is written as ______.",
        options: ["10", "100", "1000", "1"],
        answer: 1,
        explanation: "One hundred adalah 100."
    },

    // --- PLACES IN TOWN (TEMPAT DI KOTA) ---
    {
        question: "Doctors work in a ______.",
        options: ["school", "hospital", "bank", "park"],
        answer: 1,
        explanation: "Dokter bekerja di 'hospital' (rumah sakit)."
    },
    {
        question: "Teachers work in a ______.",
        options: ["hospital", "school", "shop", "zoo"],
        answer: 1,
        explanation: "Guru bekerja di 'school' (sekolah)."
    },
    {
        question: "We buy books in a ______.",
        options: ["bookstore", "library", "pharmacy", "bakery"],
        answer: 0,
        explanation: "Membeli buku di 'bookstore' (toko buku)."
    },
    {
        question: "We borrow books from a ______.",
        options: ["bookstore", "library", "bank", "market"],
        answer: 1,
        explanation: "Meminjam buku di 'library' (perpustakaan)."
    },
    {
        question: "We see animals in a ______.",
        options: ["park", "zoo", "museum", "cinema"],
        answer: 1,
        explanation: "Melihat binatang di 'zoo' (kebun binatang)."
    },

    // --- FOOD & DRINK (MAKANAN & MINUMAN) ---
    {
        question: "I want to drink a cup of ______.",
        options: ["bread", "rice", "coffee", "apple"],
        answer: 2,
        explanation: "Yang bisa diminum dalam cangkir (cup) adalah 'coffee'."
    },
    {
        question: "Can I have a slice of ______?",
        options: ["milk", "pizza", "water", "sugar"],
        answer: 1,
        explanation: "Kata 'slice' (sepotong) biasa digunakan untuk 'pizza' atau 'bread'."
    },
    {
        question: "I eat ______ for breakfast.",
        options: ["water", "juice", "bread", "tea"],
        answer: 2,
        explanation: "Yang dimakan (eat) adalah 'bread' (roti), sisanya minuman."
    },
    {
        question: "Rabbits like to eat ______.",
        options: ["carrots", "meat", "fish", "bones"],
        answer: 0,
        explanation: "Kelinci suka makan 'carrots' (wortel)."
    },
    {
        question: "Monkeys like to eat ______.",
        options: ["grass", "bananas", "chocolate", "pizza"],
        answer: 1,
        explanation: "Monyet suka makan 'bananas' (pisang)."
    },

    // --- PREPOSITIONS OF MOVEMENT (ARAH) ---
    {
        question: "Go ______ the stairs (naik).",
        options: ["down", "up", "in", "at"],
        answer: 1,
        explanation: "Naik tangga = 'Go up'."
    },
    {
        question: "Go ______ the room (masuk).",
        options: ["out", "into", "on", "up"],
        answer: 1,
        explanation: "Masuk ke dalam ruangan = 'Go into'."
    },
    {
        question: "Walk ______ the street (menyeberang).",
        options: ["across", "through", "under", "between"],
        answer: 0,
        explanation: "Menyeberang jalan = 'Walk across'."
    },

    // --- COMMON GREETINGS (SALAM) ---
    {
        question: "Good morning! Answer: ______",
        options: ["Good night", "Good morning", "Goodbye", "Thank you"],
        answer: 1,
        explanation: "Jika disapa 'Good morning', jawabannya juga 'Good morning'."
    },
    {
        question: "How are you? Answer: ______",
        options: ["I am fine", "I am nine", "Yes, I do", "No, I don't"],
        answer: 0,
        explanation: "Menanyakan kabar dijawab dengan 'I am fine' (Saya baik)."
    },
    {
        question: "Nice to meet you. Answer: ______",
        options: ["You are welcome", "Nice to meet you too", "I am sorry", "Good luck"],
        answer: 1,
        explanation: "Senang bertemu denganmu, dijawab 'Nice to meet you too'."
    },
    {
        question: "Thank you. Answer: ______",
        options: ["You are welcome", "I am fine", "Goodbye", "Please"],
        answer: 0,
        explanation: "Terima kasih dijawab dengan 'You are welcome' (Sama-sama)."
    },

    // --- GRAMMAR TRAPS (JEBAKAN UMUM) ---
    {
        question: "I ______ 10 years old. (Menyatakan umur)",
        options: ["have", "am", "is", "has"],
        answer: 1,
        explanation: "Dalam bahasa Inggris, umur menggunakan to be (am/is/are), BUKAN have."
    },
    {
        question: "She is married ______ him.",
        options: ["with", "to", "at", "by"],
        answer: 1,
        explanation: "Menikah dengan seseorang frasanya adalah 'married TO', bukan 'with'."
    },
    {
        question: "I am interested ______ music.",
        options: ["on", "at", "in", "for"],
        answer: 2,
        explanation: "Tertarik pada sesuatu frasanya adalah 'interested IN'."
    },
    {
        question: "I am afraid ______ spiders.",
        options: ["of", "with", "by", "to"],
        answer: 0,
        explanation: "Takut akan sesuatu frasanya adalah 'afraid OF'."
    },

    // --- SEASONS & NATURE (ALAM) ---
    {
        question: "It is hot in ______ (musim panas).",
        options: ["winter", "summer", "spring", "autumn"],
        answer: 1,
        explanation: "Musim panas disebut 'summer'."
    },
    {
        question: "It snows in ______ (musim dingin).",
        options: ["summer", "winter", "spring", "fall"],
        answer: 1,
        explanation: "Salju turun di musim dingin 'winter'."
    },
    {
        question: "Trees have green ______.",
        options: ["leaves", "leafs", "leaf", "roots"],
        answer: 0,
        explanation: "Daun-daun (jamak) disebut 'leaves' (bentuk tunggal: leaf)."
    },
    {
        question: "The sun rises in the ______.",
        options: ["west", "east", "north", "south"],
        answer: 1,
        explanation: "Matahari terbit di timur ('east')."
    },
    {
        question: "The sun sets in the ______.",
        options: ["east", "west", "north", "south"],
        answer: 1,
        explanation: "Matahari terbenam di barat ('west')."
    },

    // --- WH- QUESTIONS (REVIEW) ---
    {
        question: "______ time is it?",
        options: ["When", "What", "Who", "Where"],
        answer: 1,
        explanation: "Menanyakan jam menggunakan 'What time'."
    },
    {
        question: "______ is that man?",
        options: ["What", "Who", "Where", "Why"],
        answer: 1,
        explanation: "Menanyakan orang menggunakan 'Who' (Siapa)."
    },
    {
        question: "______ is your birthday?",
        options: ["Who", "When", "Where", "Which"],
        answer: 1,
        explanation: "Menanyakan waktu/tanggal menggunakan 'When' (Kapan)."
    },
    {
        question: "I eat breakfast ______ the morning.",
        options: ["at", "on", "in", "to"],
        answer: 2,
        explanation: "Untuk bagian hari (morning, afternoon, evening), gunakan 'in'."
    },
    {
        question: "I sleep ______ night.",
        options: ["in", "on", "at", "to"],
        answer: 2,
        explanation: "Pengecualian! Khusus untuk 'night' (malam), gunakan 'at'."
    },
    {
        question: "My birthday is ______ May 15th.",
        options: ["in", "on", "at", "of"],
        answer: 1,
        explanation: "Jika tanggalnya lengkap (ada angka tanggalnya), gunakan 'on'."
    },
    {
        question: "The party is ______ Sunday morning.",
        options: ["in", "at", "on", "to"],
        answer: 2,
        explanation: "Jika ada nama hari (Sunday), meski diikuti morning, tetap gunakan 'on'."
    },
    {
        question: "School starts ______ 7 o'clock.",
        options: ["on", "in", "at", "for"],
        answer: 2,
        explanation: "Untuk jam yang spesifik, gunakan 'at'."
    },

    // --- ADJECTIVES (KATA SIFAT & LAWAN KATA) ---
    {
        question: "The room is dirty. Please ______ it.",
        options: ["clean", "dirty", "messy", "dark"],
        answer: 0,
        explanation: "Lawan kata kotor (dirty) adalah bersih (clean)."
    },
    {
        question: "He is rich. He has much ______.",
        options: ["food", "money", "water", "time"],
        answer: 1,
        explanation: "Orang kaya (rich) identik dengan memiliki banyak uang (money)."
    },
    {
        question: "The box is empty. There is ______ inside.",
        options: ["something", "everything", "nothing", "anything"],
        answer: 2,
        explanation: "Jika kosong (empty), berarti tidak ada apa-apa (nothing) di dalamnya."
    },
    {
        question: "This bag is heavy. I cannot ______ it.",
        options: ["lift", "eat", "drink", "read"],
        answer: 0,
        explanation: "Jika tas berat (heavy), maka susah diangkat (lift)."
    },
    {
        question: "The knife is sharp. Be ______.",
        options: ["careful", "careless", "happy", "sad"],
        answer: 0,
        explanation: "Jika pisau tajam, kita harus hati-hati (careful)."
    },

    // --- DAILY OBJECTS (BENDA SEHARI-HARI) ---
    {
        question: "I use a ______ to cut paper.",
        options: ["spoon", "scissors", "fork", "plate"],
        answer: 1,
        explanation: "Alat untuk memotong kertas adalah gunting (scissors)."
    },
    {
        question: "I look at myself in the ______.",
        options: ["window", "wall", "mirror", "door"],
        answer: 2,
        explanation: "Kita melihat diri sendiri di cermin (mirror)."
    },
    {
        question: "I keep my money in a ______.",
        options: ["wallet", "shoe", "hat", "sock"],
        answer: 0,
        explanation: "Tempat menyimpan uang adalah dompet (wallet)."
    },
    {
        question: "I open the door with a ______.",
        options: ["key", "lock", "hammer", "saw"],
        answer: 0,
        explanation: "Membuka pintu menggunakan kunci (key)."
    },
    {
        question: "I wear ______ to help me see better.",
        options: ["hat", "shoes", "glasses", "gloves"],
        answer: 2,
        explanation: "Alat bantu melihat adalah kacamata (glasses)."
    },

    // --- VERB + PREPOSITION PAIRS (PASANGAN KATA) ---
    {
        question: "Please wait ______ me.",
        options: ["to", "for", "at", "in"],
        answer: 1,
        explanation: "Menunggu seseorang selalu 'wait FOR'."
    },
    {
        question: "Look ______ that bird!",
        options: ["at", "in", "on", "to"],
        answer: 0,
        explanation: "Melihat ke arah sesuatu adalah 'look AT'."
    },
    {
        question: "I agree ______ you.",
        options: ["to", "at", "with", "on"],
        answer: 2,
        explanation: "Setuju dengan seseorang adalah 'agree WITH'."
    },
    {
        question: "She is good ______ Math.",
        options: ["in", "at", "on", "with"],
        answer: 1,
        explanation: "Ahli/jago dalam suatu pelajaran menggunakan 'good AT'."
    },

    // --- BASIC CONJUNCTIONS (KATA HUBUNG) ---
    {
        question: "I wash my hands ______ I eat.",
        options: ["after", "before", "while", "during"],
        answer: 1,
        explanation: "Mencuci tangan dilakukan 'sebelum' (before) makan."
    },
    {
        question: "I brush my teeth ______ I eat.",
        options: ["before", "after", "while", "during"],
        answer: 1,
        explanation: "Biasanya gosok gigi dilakukan 'setelah' (after) makan."
    },
    {
        question: "I am studying ______ watching TV.",
        options: ["and", "but", "or", "so"],
        answer: 0,
        explanation: "Melakukan dua hal sekaligus digabungkan dengan 'and'."
    },
    {
        question: "Do you like tea ______ coffee?",
        options: ["and", "or", "but", "so"],
        answer: 1,
        explanation: "Jika memberikan pilihan (pertanyaan), gunakan 'or' (atau)."
    },

    // --- WH- QUESTIONS (PILIHAN) ---
    {
        question: "______ color do you like? Red or Blue?",
        options: ["What", "Which", "Who", "Where"],
        answer: 1,
        explanation: "Jika disuruh memilih dari pilihan yang terbatas, gunakan 'Which'."
    },
    {
        question: "______ bag is yours? The big one or the small one?",
        options: ["What", "Which", "Who", "When"],
        answer: 1,
        explanation: "Memilih benda spesifik menggunakan 'Which'."
    },

    // --- QUANTIFIERS (BANYAK/SEDIKIT) ---
    {
        question: "There are too ______ people here.",
        options: ["much", "many", "little", "any"],
        answer: 1,
        explanation: "Orang (people) bisa dihitung, jadi gunakan 'many'."
    },
    {
        question: "There is too ______ sugar in my tea.",
        options: ["many", "much", "few", "some"],
        answer: 1,
        explanation: "Gula (sugar) tidak bisa dihitung butirannya, jadi gunakan 'much'."
    },
    {
        question: "I have a ______ coins.",
        options: ["few", "little", "much", "any"],
        answer: 0,
        explanation: "Koin bisa dihitung, jika sedikit gunakan 'few'."
    },

    // --- COLORS & NATURE ---
    {
        question: "The grass is ______.",
        options: ["blue", "red", "green", "yellow"],
        answer: 2,
        explanation: "Rumput berwarna hijau (green)."
    },
    {
        question: "The sky is ______.",
        options: ["green", "blue", "yellow", "brown"],
        answer: 1,
        explanation: "Langit berwarna biru (blue)."
    },
    {
        question: "Snow is ______.",
        options: ["black", "white", "red", "green"],
        answer: 1,
        explanation: "Salju berwarna putih (white)."
    },
    {
        question: "Bananas are ______.",
        options: ["purple", "yellow", "blue", "pink"],
        answer: 1,
        explanation: "Pisang matang berwarna kuning (yellow)."
    },

    // --- BASIC VERBS (ACTION) ---
    {
        question: "Birds use wings to ______.",
        options: ["swim", "run", "fly", "jump"],
        answer: 2,
        explanation: "Burung menggunakan sayap untuk terbang (fly)."
    },
    {
        question: "Fish use fins to ______.",
        options: ["fly", "swim", "walk", "run"],
        answer: 1,
        explanation: "Ikan menggunakan sirip untuk berenang (swim)."
    },
    {
        question: "I use my legs to ______.",
        options: ["write", "eat", "walk", "listen"],
        answer: 2,
        explanation: "Kaki digunakan untuk berjalan (walk)."
    },
    {
        question: "I use my mouth to ______.",
        options: ["see", "hear", "speak", "walk"],
        answer: 2,
        explanation: "Mulut digunakan untuk berbicara (speak) atau makan."
    },

    // --- PRONOUNS (POSSESSIVE PRONOUNS) ---
    {
        question: "This book is not yours. It is ______ (milikku).",
        options: ["my", "mine", "me", "I"],
        answer: 1,
        explanation: "'Mine' digunakan di akhir kalimat tanpa diikuti benda lagi."
    },
    {
        question: "That car is not ours. It is ______ (milik mereka).",
        options: ["their", "theirs", "them", "they"],
        answer: 1,
        explanation: "'Theirs' artinya milik mereka (posisi di akhir kalimat)."
    },
    {
        question: "Is this pen ______ (milikmu)?",
        options: ["your", "yours", "you", "we"],
        answer: 1,
        explanation: "Milikmu di akhir kalimat adalah 'yours'."
    },

    // --- DEMONSTRATIVES (THIS/THAT/THESE/THOSE) ---
    {
        question: "______ birds (jauh) are flying high.",
        options: ["This", "That", "These", "Those"],
        answer: 3,
        explanation: "Benda jamak (birds) dan jauh (flying high/di atas), gunakan 'Those'."
    },
    {
        question: "______ flower (dekat) smells good.",
        options: ["This", "That", "These", "Those"],
        answer: 0,
        explanation: "Benda tunggal (flower) dan dekat (bisa dicium baunya), gunakan 'This'."
    },

    // --- GENERAL KNOWLEDGE (PENGETAHUAN UMUM) ---
    {
        question: "Jakarta is a ______.",
        options: ["country", "city", "village", "river"],
        answer: 1,
        explanation: "Jakarta adalah sebuah kota (city)."
    },
    {
        question: "Indonesia is a ______.",
        options: ["city", "country", "town", "street"],
        answer: 1,
        explanation: "Indonesia adalah sebuah negara (country)."
    },
    {
        question: "English is a ______.",
        options: ["country", "language", "city", "food"],
        answer: 1,
        explanation: "English adalah sebuah bahasa (language)."
    },

    // --- IMPERATIVE (LARANGAN) ---
    {
        question: "______ smoke here. It is dangerous.",
        options: ["Not", "No", "Don't", "Doesn't"],
        answer: 2,
        explanation: "Larangan selalu menggunakan 'Don't' di awal kalimat."
    },
    {
        question: "______ litter! (Jangan buang sampah sembarangan)",
        options: ["Don't", "No", "Not", "Aren't"],
        answer: 0,
        explanation: "Gunakan 'Don't' untuk melarang."
    },
    {
        question: "Please ______ quiet.",
        options: ["be", "is", "are", "do"],
        answer: 0,
        explanation: "Jika diikuti kata sifat (quiet), gunakan 'be'."
    },
    {
        question: "I am ______ to visit my grandmother tomorrow.",
        options: ["go", "gone", "going", "goes"],
        answer: 2,
        explanation: "Pola rencana masa depan: To Be + going to + Verb 1. Jadi, 'I am going to visit'."
    },
    {
        question: "She ______ going to buy a new phone.",
        options: ["is", "am", "are", "be"],
        answer: 0,
        explanation: "Pasangan subjek 'She' adalah to be 'is'."
    },
    {
        question: "We are going to ______ football next week.",
        options: ["playing", "play", "played", "plays"],
        answer: 1,
        explanation: "Setelah 'going to', kata kerja harus kembali ke bentuk dasar/asli ('play')."
    },
    {
        question: "______ you going to cook dinner?",
        options: ["Do", "Is", "Are", "Did"],
        answer: 2,
        explanation: "Pertanyaan dengan 'going to' diawali dengan To Be. Pasangan 'You' adalah 'Are'."
    },
    {
        question: "They are NOT ______ to come.",
        options: ["go", "going", "goes", "gone"],
        answer: 1,
        explanation: "Bentuk negatif tetap menggunakan 'going to'."
    },

    // --- HOW QUESTIONS (BERAPA & BAGAIMANA) ---
    {
        question: "______ much is this shirt? (Menanyakan harga)",
        options: ["How", "What", "Who", "Where"],
        answer: 0,
        explanation: "Menanyakan harga selalu menggunakan 'How much'."
    },
    {
        question: "______ many brothers do you have? (Menanyakan jumlah)",
        options: ["How", "What", "Who", "Where"],
        answer: 0,
        explanation: "Menanyakan jumlah benda yang bisa dihitung (brothers) menggunakan 'How many'."
    },
    {
        question: "______ do you go to school? (Menanyakan cara)",
        options: ["What", "How", "Who", "When"],
        answer: 1,
        explanation: "Menanyakan cara (naik apa/bagaimana) menggunakan 'How'. Jawabannya bisa 'By bus'."
    },
    {
        question: "______ far is your house? (Menanyakan jarak)",
        options: ["How", "What", "Who", "Which"],
        answer: 0,
        explanation: "Menanyakan jarak menggunakan 'How far'."
    },
    {
        question: "______ long is the movie? (Menanyakan durasi)",
        options: ["How", "What", "Who", "When"],
        answer: 0,
        explanation: "Menanyakan durasi waktu menggunakan 'How long'."
    },

    // --- DIRECTIONS (ARAH JALAN) ---
    {
        question: "Go ______ (lurus) until the traffic light.",
        options: ["left", "right", "straight", "back"],
        answer: 2,
        explanation: "Jalan lurus = 'Go straight'."
    },
    {
        question: "Turn ______ (belok kiri).",
        options: ["left", "right", "straight", "up"],
        answer: 0,
        explanation: "Kiri adalah 'left'."
    },
    {
        question: "Turn ______ (belok kanan).",
        options: ["left", "right", "straight", "down"],
        answer: 1,
        explanation: "Kanan adalah 'right'."
    },
    {
        question: "The bank is on the ______ (pojok).",
        options: ["corner", "side", "wall", "floor"],
        answer: 0,
        explanation: "Di pojokan jalan disebut 'on the corner'."
    },
    {
        question: "Cross the ______ (seberangi jalan).",
        options: ["street", "wall", "house", "car"],
        answer: 0,
        explanation: "Menyeberang jalan = 'Cross the street'."
    },

    // --- KITCHEN UTENSILS (ALAT DAPUR) ---
    {
        question: "I drink water from a ______.",
        options: ["plate", "bowl", "glass", "fork"],
        answer: 2,
        explanation: "Minum air menggunakan 'glass' (gelas)."
    },
    {
        question: "I eat soup with a ______.",
        options: ["fork", "knife", "spoon", "plate"],
        answer: 2,
        explanation: "Makan sup menggunakan 'spoon' (sendok)."
    },
    {
        question: "I cut meat with a ______.",
        options: ["spoon", "knife", "fork", "glass"],
        answer: 1,
        explanation: "Memotong daging menggunakan 'knife' (pisau)."
    },
    {
        question: "I put rice on a ______.",
        options: ["glass", "cup", "plate", "bottle"],
        answer: 2,
        explanation: "Menaruh nasi di atas 'plate' (piring)."
    },
    {
        question: "I drink tea from a ______.",
        options: ["bowl", "cup", "plate", "spoon"],
        answer: 1,
        explanation: "Minum teh (biasanya panas) menggunakan 'cup' (cangkir)."
    },

    // --- FRUITS & VEGETABLES (BUAH & SAYUR) ---
    {
        question: "An orange is ______ (warna).",
        options: ["red", "orange", "blue", "purple"],
        answer: 1,
        explanation: "Buah jeruk (orange) warnanya jingga (orange)."
    },
    {
        question: "A strawberry is ______ (warna).",
        options: ["red", "blue", "yellow", "black"],
        answer: 0,
        explanation: "Stroberi berwarna merah (red)."
    },
    {
        question: "Grapes are usually ______ or green.",
        options: ["purple", "orange", "white", "blue"],
        answer: 0,
        explanation: "Anggur biasanya berwarna ungu (purple) atau hijau."
    },
    {
        question: "A lemon is ______ (rasa).",
        options: ["sweet", "sour", "spicy", "salty"],
        answer: 1,
        explanation: "Lemon rasanya 'sour' (asam)."
    },
    {
        question: "Candy is ______ (rasa).",
        options: ["sour", "bitter", "sweet", "hot"],
        answer: 2,
        explanation: "Permen rasanya 'sweet' (manis)."
    },

    // --- ADVERBS OF FREQUENCY (POSISI KATA) ---
    {
        question: "I ______ eat breakfast at 7 AM. (Selalu)",
        options: ["always", "never", "rarely", "sometimes"],
        answer: 0,
        explanation: "'Always' diletakkan SEBELUM kata kerja (eat)."
    },
    {
        question: "He is ______ late. (Tidak pernah)",
        options: ["always", "never", "often", "usually"],
        answer: 1,
        explanation: "Jika ada To Be (is), kata keterangan diletakkan SETELAH To Be. 'He is never late'."
    },
    {
        question: "We ______ play football on Sundays. (Biasanya)",
        options: ["never", "rarely", "usually", "hardly"],
        answer: 2,
        explanation: "Biasanya = 'Usually'."
    },
    {
        question: "They ______ watch TV. (Jarang)",
        options: ["always", "rarely", "usually", "often"],
        answer: 1,
        explanation: "Jarang = 'Rarely' atau 'Seldom'."
    },

    // --- POSSESSIVE 'S (KEPEMILIKAN NAMA) ---
    {
        question: "This is ______ house. (Rumah milik Budi)",
        options: ["Budi", "Budis", "Budi's", "Budies"],
        answer: 2,
        explanation: "Tambahkan 's pada nama pemilik: 'Budi's house'."
    },
    {
        question: "Where is ______ bag? (Tas milik Sarah)",
        options: ["Sarah", "Sarah's", "Sarahs", "Sarah is"],
        answer: 1,
        explanation: "Tas milik Sarah = 'Sarah's bag'."
    },
    {
        question: "These are my ______ shoes. (Sepatu ayah saya)",
        options: ["fathers", "father's", "father", "fathers'"],
        answer: 1,
        explanation: "Sepatu milik ayah = 'father's shoes'."
    },

    // --- THIS/THAT vs IT/THEY (PRONOUNS) ---
    {
        question: "Do you like this book? Yes, I like ______.",
        options: ["this", "it", "that", "them"],
        answer: 1,
        explanation: "Untuk menggantikan benda tunggal (book) yang sudah disebutkan, gunakan 'it'."
    },
    {
        question: "Do you like these shoes? Yes, I like ______.",
        options: ["it", "them", "that", "this"],
        answer: 1,
        explanation: "Untuk menggantikan benda jamak (shoes), gunakan 'them'."
    },
    {
        question: "Where is your car? ______ is in the garage.",
        options: ["It", "They", "He", "She"],
        answer: 0,
        explanation: "Mobil (benda tunggal) kata gantinya adalah 'It'."
    },

    // --- TIME (JAM - QUARTER/HALF) ---
    {
        question: "It is 07:15. It is a ______ past seven.",
        options: ["half", "quarter", "clock", "time"],
        answer: 1,
        explanation: "Lewat 15 menit disebut 'quarter past'."
    },
    {
        question: "It is 07:30. It is ______ past seven.",
        options: ["quarter", "half", "clock", "mid"],
        answer: 1,
        explanation: "Lewat 30 menit disebut 'half past'."
    },
    {
        question: "It is 07:45. It is a quarter ______ eight.",
        options: ["past", "to", "for", "at"],
        answer: 1,
        explanation: "Kurang 15 menit menuju jam 8, disebut 'quarter TO eight'."
    },

    // --- CONJUNCTIONS (BECAUSE vs SO) ---
    {
        question: "I am hungry, ______ I will eat.",
        options: ["because", "so", "but", "or"],
        answer: 1,
        explanation: "'So' (jadi/maka) digunakan untuk menyatakan hasil/akibat. Lapar -> Makan."
    },
    {
        question: "I eat ______ I am hungry.",
        options: ["so", "because", "but", "and"],
        answer: 1,
        explanation: "'Because' (karena) digunakan untuk menyatakan alasan. Makan <- Lapar."
    },
    {
        question: "It is raining, ______ I take an umbrella.",
        options: ["because", "but", "so", "or"],
        answer: 2,
        explanation: "Hujan -> (maka) Bawa payung. Gunakan 'so'."
    },

    // --- MODALS (CAN/COULD - POLITE REQUEST) ---
    {
        question: "______ you help me, please?",
        options: ["Do", "Are", "Can", "Have"],
        answer: 2,
        explanation: "Untuk meminta tolong dengan sopan, gunakan 'Can' atau 'Could'."
    },
    {
        question: "______ I borrow your pen?",
        options: ["Am", "Do", "May", "Will"],
        answer: 2,
        explanation: "'May' adalah bentuk yang sangat sopan untuk meminta izin."
    },

    // --- SEASONS (MUSIM) ---
    {
        question: "Indonesia has two seasons: Dry season and ______ season.",
        options: ["snowy", "rainy", "windy", "sunny"],
        answer: 1,
        explanation: "Indonesia punya musim kemarau (dry) dan musim hujan (rainy)."
    },
    {
        question: "In Europe, after winter comes ______.",
        options: ["summer", "spring", "autumn", "fall"],
        answer: 1,
        explanation: "Setelah musim dingin (winter) adalah musim semi (spring)."
    },

    // --- MISC VOCABULARY ---
    {
        question: "My father's wife is my ______.",
        options: ["sister", "grandmother", "mother", "aunt"],
        answer: 2,
        explanation: "Istri dari ayahku adalah ibuku (mother)."
    },
    {
        question: "The opposite of 'Start' is ______.",
        options: ["Begin", "Go", "Finish", "Run"],
        answer: 2,
        explanation: "Lawan kata Mulai (Start) adalah Selesai (Finish)."
    },
    {
        question: "The opposite of 'Buy' is ______.",
        options: ["Sell", "Pay", "Get", "Take"],
        answer: 0,
        explanation: "Lawan kata Membeli (Buy) adalah Menjual (Sell)."
    },
    {
        question: "I check the date on the ______.",
        options: ["clock", "calendar", "picture", "wall"],
        answer: 1,
        explanation: "Kita mengecek tanggal di kalender (calendar)."
    },
    {
        question: "We buy medicine at the ______.",
        options: ["bakery", "pharmacy", "library", "school"],
        answer: 1,
        explanation: "Kita membeli obat di apotek (pharmacy/drugstore)."
    }
];