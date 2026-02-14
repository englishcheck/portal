const questionsSource = [
    {
        question: "I ______ my homework when the phone rang.",
        options: ["did", "was doing", "have done", "am doing"],
        answer: 1,
        explanation: "Gunakan 'Past Continuous' (was doing) untuk tindakan yang sedang berlangsung di masa lampau ketika tindakan lain (phone rang) menyela."
    },
    {
        question: "She ______ to London three times this year.",
        options: ["has been", "gone", "was", "is going"],
        answer: 0,
        explanation: "Gunakan 'Present Perfect' (has been) untuk menceritakan pengalaman atau kejadian yang terjadi dalam periode waktu yang belum selesai (this year)."
    },
    {
        question: "If I ______ enough money, I would buy that car.",
        options: ["have", "had", "would have", "having"],
        answer: 1,
        explanation: "Ini adalah 'Conditional Sentence Type 2' (pengandaian masa kini). Polanya adalah: If + Past Simple, would + V1. Jadi jawabannya adalah 'had'."
    },
    {
        question: "The letter ______ by the secretary yesterday morning.",
        options: ["writes", "wrote", "was written", "is written"],
        answer: 2,
        explanation: "Kalimat pasif (Passive Voice) di masa lampau (yesterday). Polanya: Subject + was/were + V3. Jadi, 'was written' adalah jawaban yang benar."
    },
    {
        question: "I look forward to ______ from you soon.",
        options: ["hear", "hearing", "heard", "hears"],
        answer: 1,
        explanation: "Setelah frasa 'look forward to', kita harus menggunakan Gerund (Verb-ing). Jadi, 'hearing' adalah bentuk yang tepat."
    },
    {
        question: "He is the man ______ car was stolen last night.",
        options: ["who", "which", "whose", "whom"],
        answer: 2,
        explanation: "Gunakan 'whose' untuk menunjukkan kepemilikan (possession) dalam Relative Clause. 'Whose car' berarti 'mobil milik pria itu'."
    },
    {
        question: "You ______ smoke in the hospital. It's forbidden.",
        options: ["don't have to", "must not", "should not", "might not"],
        answer: 1,
        explanation: "'Must not' digunakan untuk larangan keras (prohibition). 'Don't have to' berarti tidak perlu (tapi boleh), sedangkan di rumah sakit itu dilarang."
    },
    {
        question: "They have lived in this house ______ 2010.",
        options: ["for", "since", "in", "at"],
        answer: 1,
        explanation: "Gunakan 'since' untuk menunjukkan titik awal waktu (tahun 2010). Gunakan 'for' jika membicarakan durasi (misal: for 10 years)."
    },
    {
        question: "She is ______ intelligent than her brother.",
        options: ["more", "most", "as", "so"],
        answer: 0,
        explanation: "Bentuk komparatif (perbandingan) untuk kata sifat panjang (intelligent) menggunakan 'more'. Polanya: more + adjective + than."
    },
    {
        question: "I wish I ______ how to play the piano.",
        options: ["know", "knew", "knowing", "have known"],
        answer: 1,
        explanation: "Saat menggunakan 'wish' untuk sesuatu yang tidak nyata saat ini, kita memundurkan tenses ke masa lampau (Past Simple). Jadi 'know' menjadi 'knew'."
    },
    {
        question: "Despite ______ late, he finished the test on time.",
        options: ["he was", "being", "of being", "is"],
        answer: 1,
        explanation: "Setelah preposisi 'despite', kita menggunakan Noun Phrase atau Gerund (Verb-ing). Kita tidak bisa langsung menggunakan subjek+verb (he was) tanpa konektor lain."
    },
    {
        question: "Can you tell me where ______?",
        options: ["is the station", "the station is", "the station", "is station"],
        answer: 1,
        explanation: "Ini adalah 'Embedded Question' (pertanyaan di dalam kalimat). Urutan katanya kembali normal: Subject + Verb ('the station is'), bukan dibalik seperti pertanyaan biasa."
    },
    {
        question: "My father stopped ______ two years ago.",
        options: ["to smoke", "smoking", "smoke", "smoked"],
        answer: 1,
        explanation: "'Stop smoking' (berhenti melakukan aktivitas merokok) berbeda dengan 'stop to smoke' (berhenti melakukan sesuatu agar bisa merokok). Konteks ini menyiratkan berhenti total."
    },
    {
        question: "The tea is ______ hot to drink.",
        options: ["very", "too", "enough", "such"],
        answer: 1,
        explanation: "'Too' digunakan untuk menyatakan sesuatu yang berlebihan dan memiliki konotasi negatif (terlalu panas sehingga tidak bisa diminum)."
    },
    {
        question: "I would rather you ______ home now.",
        options: ["go", "went", "gone", "to go"],
        answer: 1,
        explanation: "Struktur 'would rather + someone + past tense' digunakan untuk menyatakan preferensi agar orang lain melakukan sesuatu saat ini/masa depan."
    },
    {
        question: "Neither the teacher nor the students ______ happy with the result.",
        options: ["is", "are", "was", "has"],
        answer: 1,
        explanation: "Dalam struktur 'Neither... nor...', verb mengikuti subjek yang paling dekat (the students). Karena jamak, gunakan 'are'."
    },
    {
        question: "It is important that he ______ the doctor immediately.",
        options: ["see", "sees", "saw", "seeing"],
        answer: 0,
        explanation: "Ini adalah bentuk 'Subjunctive'. Setelah frasa penting/saran (important that), kata kerja kembali ke bentuk dasar (base form) tanpa 's' meskipun subjeknya 'he'."
    },
    {
        question: "We ran out of gas because we ______ to fill the tank.",
        options: ["forget", "forgot", "had forgotten", "have forgotten"],
        answer: 2,
        explanation: "Gunakan 'Past Perfect' (had forgotten) untuk kejadian yang terjadi *sebelum* kejadian masa lampau lainnya (ran out of gas)."
    },
    {
        question: "______ strictly, spiders are not insects.",
        options: ["Speaking", "Speak", "Spoken", "To speak"],
        answer: 0,
        explanation: "'Speaking strictly' adalah participle phrase yang umum digunakan. Ini berfungsi sebagai keterangan cara."
    },
    {
        question: "Unless you ______ harder, you will fail the exam.",
        options: ["study", "don't study", "will study", "studied"],
        answer: 0,
        explanation: "'Unless' berarti 'if... not'. Jadi kalimatnya sudah bermakna negatif, tidak perlu 'don't' lagi. Gunakan Present Simple untuk masa depan dalam klausa pengandaian."
    },
    {
        question: "She made her children ______ their vegetables.",
        options: ["eating", "to eat", "eat", "ate"],
        answer: 2,
        explanation: "Kata kerja kausatif 'make' diikuti oleh objek dan 'bare infinitive' (V1 tanpa to). Pola: make + person + verb."
    },
    {
        question: "I am not used to ______ up so early.",
        options: ["get", "getting", "got", "be getting"],
        answer: 1,
        explanation: "'Be used to' (terbiasa dengan) diikuti oleh Gerund (V-ing). Jangan terkecoh dengan 'used to' (dulu terbiasa) yang diikuti V1."
    },
    {
        question: "By this time next year, I ______ my degree.",
        options: ["will finish", "will have finished", "finish", "am finishing"],
        answer: 1,
        explanation: "Gunakan 'Future Perfect' (will have + V3) untuk menyatakan tindakan yang akan *sudah* selesai pada titik tertentu di masa depan."
    },
    {
        question: "Only when the bus stopped ______ get off.",
        options: ["we did", "did we", "we were", "were we"],
        answer: 1,
        explanation: "Ketika kalimat dimulai dengan 'Only when', terjadi 'inversion' (pembalikan). Polanya seperti kalimat tanya: Auxiliary + Subject + Verb."
    },
    {
        question: "It was ______ a boring movie that I fell asleep.",
        options: ["so", "such", "very", "too"],
        answer: 1,
        explanation: "Gunakan 'such' sebelum Noun Phrase (a boring movie). Gunakan 'so' jika hanya diikuti Adjective (so boring)."
    },
    {
        question: "I'll give you a call as soon as I ______.",
        options: ["arrive", "will arrive", "arrived", "am arriving"],
        answer: 0,
        explanation: "Dalam 'time clause' (seperti as soon as, when), kita menggunakan Present Simple untuk merujuk ke masa depan, bukan 'will'."
    },
    {
        question: "There is ______ milk left in the fridge.",
        options: ["few", "a few", "little", "many"],
        answer: 2,
        explanation: "'Milk' adalah uncountable noun (tidak bisa dihitung). Gunakan 'little' untuk jumlah sedikit. 'Few' hanya untuk benda yang bisa dihitung."
    },
    {
        question: "He asked me if I ______ seen the movie yet.",
        options: ["have", "had", "did", "was"],
        answer: 1,
        explanation: "Dalam 'Reported Speech', tenses mundur satu langkah. 'Have seen' (Present Perfect) berubah menjadi 'Had seen' (Past Perfect)."
    },
    {
        question: "You'd better ______ a doctor before it gets worse.",
        options: ["see", "to see", "seeing", "saw"],
        answer: 0,
        explanation: "'Had better' berfungsi seperti modal verb dan diikuti oleh 'bare infinitive' (V1 tanpa to)."
    },
    {
        question: "Not only ______ the car, but he also crashed it.",
        options: ["he stole", "did he steal", "he did steal", "stole he"],
        answer: 1,
        explanation: "Inversi diperlukan setelah 'Not only' di awal kalimat. Pola: Not only + Auxiliary + Subject + Verb."
    },
    {
        question: "The bridge ______ built right now.",
        options: ["is", "is being", "has been", "was"],
        answer: 1,
        explanation: "Passive Voice dalam Present Continuous. Pola: is/am/are + being + V3. Ini menunjukkan pekerjaan sedang berlangsung."
    },
    {
        question: "I regret ______ you that your application was rejected.",
        options: ["tell", "to tell", "telling", "told"],
        answer: 1,
        explanation: "'Regret to tell' digunakan untuk menyampaikan berita buruk (formal). 'Regret telling' berarti menyesal telah melakukan sesuatu di masa lalu."
    },
    {
        question: "Had I known about the party, I ______ gone.",
        options: ["would have", "would", "will have", "had"],
        answer: 0,
        explanation: "Inversi dari Conditional Type 3 (If I had known...). Bagian utama kalimat membutuhkan 'would have + V3'."
    },
    {
        question: "Everything depends ______ the weather.",
        options: ["of", "in", "on", "at"],
        answer: 2,
        explanation: "Kata kerja 'depend' selalu berpasangan dengan preposisi 'on'."
    },
    {
        question: "He speaks ______ English nor French.",
        options: ["either", "neither", "both", "not"],
        answer: 1,
        explanation: "Pasangan dari 'nor' adalah 'neither'. (Neither... nor... = Tidak keduanya)."
    },
    {
        question: "Please let me ______.",
        options: ["to go", "go", "going", "gone"],
        answer: 1,
        explanation: "Kata 'let' diikuti oleh objek dan 'bare infinitive' (V1 tanpa to). Pola: let + person + verb."
    },
    {
        question: "It's time we ______ home.",
        options: ["go", "went", "have gone", "will go"],
        answer: 1,
        explanation: "Setelah frasa 'It's time', kita menggunakan Past Simple untuk menyatakan bahwa sesuatu seharusnya sudah terjadi sekarang."
    },
    {
        question: "The man ______ I spoke to was very helpful.",
        options: ["who", "whom", "which", "whose"],
        answer: 1,
        explanation: "'Whom' adalah bentuk objek untuk orang (objek dari preposisi 'to'). Meskipun 'who' sering dipakai dalam percakapan informal, 'whom' lebih tepat secara gramatikal di sini."
    },
    {
        question: "Hardly had I arrived ______ the phone rang.",
        options: ["when", "than", "after", "while"],
        answer: 0,
        explanation: "Pasangan dari 'Hardly... had...' adalah 'when'. Ini berarti sesuatu terjadi segera setelah kejadian lain."
    },
    {
        question: "I differ ______ you on this matter.",
        options: ["with", "from", "to", "against"],
        answer: 0,
        explanation: "Kita bisa menggunakan 'differ with' seseorang (tentang pendapat). 'Differ from' biasanya untuk membedakan sifat benda/orang."
    },
    {
        question: "Would you mind ______ the window?",
        options: ["open", "to open", "opening", "opened"],
        answer: 2,
        explanation: "Frasa 'Would you mind' selalu diikuti oleh Gerund (V-ing)."
    },
    {
        question: "She is capable ______ solving the problem.",
        options: ["of", "to", "in", "at"],
        answer: 0,
        explanation: "Kata sifat 'capable' berpasangan dengan preposisi 'of', diikuti V-ing."
    },
    {
        question: "The police ______ investigating the crime.",
        options: ["is", "are", "was", "has"],
        answer: 1,
        explanation: "Kata 'police' selalu dianggap jamak (plural) dalam bahasa Inggris. Jadi gunakan 'are'."
    },
    {
        question: "I prefer tea ______ coffee.",
        options: ["than", "to", "from", "over"],
        answer: 1,
        explanation: "Pola preferensi: prefer A 'to' B. Jangan gunakan 'than' setelah prefer (kecuali dalam 'would rather... than')."
    },
    {
        question: "______ the rain, we went for a walk.",
        options: ["Although", "Despite", "Even though", "However"],
        answer: 1,
        explanation: "'The rain' adalah Noun Phrase. 'Despite' diikuti noun, sedangkan 'Although' harus diikuti kalimat lengkap (subjek + verb)."
    },
    {
        question: "Nobody knows the answer, ______?",
        options: ["do they", "don't they", "does he", "doesn't he"],
        answer: 0,
        explanation: "Question Tag. 'Nobody' bermakna negatif, jadi tag-nya positif. Kata ganti untuk 'nobody/everybody' dalam tag adalah 'they', jadi verb-nya 'do'."
    },
    {
        question: "This is the first time I ______ sushi.",
        options: ["eat", "ate", "have eaten", "eating"],
        answer: 2,
        explanation: "Setelah frasa 'This is the first time', kita wajib menggunakan Present Perfect Tense."
    },
    {
        question: "Try to avoid ______ mistakes.",
        options: ["make", "to make", "making", "made"],
        answer: 2,
        explanation: "Kata kerja 'avoid' selalu diikuti oleh Gerund (V-ing)."
    },
    {
        question: "We should get someone ______ the roof.",
        options: ["fix", "to fix", "fixing", "fixed"],
        answer: 1,
        explanation: "Causative 'get': get + person + 'to' + verb. (Berbeda dengan 'have' + person + verb)."
    },
    {
        question: "If only I ______ taller.",
        options: ["am", "was", "were", "be"],
        answer: 2,
        explanation: "Dalam kalimat pengandaian (subjunctive), 'to be' untuk semua subjek adalah 'were'. 'If only I were...'."
    },
    {
        question: "By the time the police arrived, the thief ______.",
        options: ["has escaped", "escaped", "had escaped", "was escaping"],
        answer: 2,
        explanation: "Kita menggunakan 'Past Perfect' (had + V3) untuk kejadian yang terjadi *sebelum* kejadian masa lalu lainnya. Polisi datang di masa lalu, tapi pencuri itu kabur *sebelum* polisi datang. Urutannya: Pencuri kabur (Past Perfect) -> Polisi datang (Past Simple)."
    },
    {
        question: "I remember ______ the door, but I can't find the key now.",
        options: ["to lock", "locking", "lock", "locked"],
        answer: 1,
        explanation: "Kata kerja 'remember' memiliki dua arti beda tergantung pasangannya. 'Remember to lock' artinya ingat *bahwa harus* mengunci (tugas). 'Remember locking' artinya ingat *telah melakukan* aksi mengunci (memori). Di sini konteksnya adalah mengingat memori masa lalu."
    },
    {
        question: "She asked me where ______ from.",
        options: ["do I come", "did I come", "I came", "come I"],
        answer: 2,
        explanation: "Ini adalah 'Indirect Question' (pertanyaan tidak langsung). Dalam kalimat positif, urutan kata tidak boleh dibalik seperti pertanyaan (Auxiliary + Subject). Urutannya harus kembali normal: Subject + Verb. Jadi 'where I came from', bukan 'where did I come'."
    },
    {
        question: "If I ______ you, I would apologize immediately.",
        options: ["am", "was", "were", "be"],
        answer: 2,
        explanation: "Ini adalah 'Conditional Type 2' (saran/pengandaian). Dalam bahasa Inggris formal dan gramatikal, 'to be' untuk semua subjek (I, He, She, It) dalam pengandaian adalah 'were', bukan 'was'. Frasa 'If I were you' adalah ungkapan baku untuk memberi saran."
    },
    {
        question: "The man ______ to at the party was very famous.",
        options: ["who spoke", "whom I spoke", "I spoke", "that spoke"],
        answer: 1,
        explanation: "Kita membutuhkan objek pronoun karena 'I' adalah subjek yang berbicara 'kepada' (to) pria itu. Bentuk formalnya adalah 'whom I spoke to' atau 'to whom I spoke'. Opsi 'who spoke' salah karena itu berarti pria itu yang berbicara, bukan saya."
    },
    {
        question: "My car needs ______.",
        options: ["repair", "to repair", "repairing", "repaired"],
        answer: 2,
        explanation: "Setelah kata kerja 'need', jika subjeknya adalah benda mati (seperti mobil) dan maknanya pasif (perlu diperbaiki), kita bisa menggunakan Gerund (V-ing). 'Needs repairing' sama artinya dengan 'needs to be repaired'."
    },
    {
        question: "He is believed ______ the richest man in town.",
        options: ["is", "to be", "being", "been"],
        answer: 1,
        explanation: "Ini adalah struktur Passive Voice khusus untuk opini umum. Polanya: Subject + Passive Verb (is believed) + To Infinitive. Jadi jawabannya 'to be'."
    },
    {
        question: "Scarcely had we started lunch ______ it began to rain.",
        options: ["than", "when", "after", "while"],
        answer: 1,
        explanation: "Pasangan kata hubung (correlative conjunction) untuk 'Scarcely' atau 'Hardly' adalah 'when'. Artinya: Baru saja mulai makan, tiba-tiba hujan. Jangan tertukar dengan 'No sooner... than'."
    },
    {
        question: "______ of the two sisters is married.",
        options: ["None", "Both", "Neither", "All"],
        answer: 2,
        explanation: "'Neither' digunakan untuk menyangkal *dua* orang/benda (tidak satu pun dari keduanya). 'None' digunakan untuk lebih dari dua. Karena ada 'two sisters', yang tepat adalah 'Neither'."
    },
    {
        question: "I'd rather you ______ make so much noise.",
        options: ["don't", "didn't", "won't", "not"],
        answer: 1,
        explanation: "Struktur 'Would rather + Subject (orang lain)' menuntut penggunaan Past Tense untuk keinginan di masa sekarang (mirip dengan 'wish'). Jadi gunakan 'didn't', bukan 'don't'."
    },
    {
        question: "It is high time we ______ something about pollution.",
        options: ["do", "did", "have done", "will do"],
        answer: 1,
        explanation: "Ungkapan 'It is high time' atau 'It is time' selalu diikuti oleh Past Simple. Ini menyatakan urgensi bahwa sesuatu seharusnya sudah dilakukan sekarang (agak terlambat)."
    },
    {
        question: "Only by working hard ______ your goals.",
        options: ["you can achieve", "can you achieve", "you will achieve", "achieve you"],
        answer: 1,
        explanation: "Ketika kalimat dimulai dengan kata 'Only' + keterangan cara/waktu, terjadi Inversi (pembalikan posisi subjek dan auxiliary). Jadi 'can you achieve', bukan 'you can achieve'."
    },
    {
        question: "I suggest that she ______ a doctor.",
        options: ["see", "sees", "saw", "seeing"],
        answer: 0,
        explanation: "Ini adalah bentuk 'Subjunctive'. Setelah kata kerja saran/perintah (suggest, recommend, insist) + that, kata kerja berikutnya harus dalam bentuk dasar (Base Form/Bare Infinitive) tanpa imbuhan 's', 'es', atau 'ed', meskipun subjeknya 'she'."
    },
    {
        question: "Not until next week ______ the results.",
        options: ["we will know", "will we know", "do we know", "we know"],
        answer: 1,
        explanation: "Frasa 'Not until' di awal kalimat memicu Inversi. Kita membalikkan auxiliary verb 'will' ke depan subjek. Struktur normalnya: We will not know until next week."
    },
    {
        question: "Let's go to the beach, ______?",
        options: ["will we", "do we", "shall we", "aren't we"],
        answer: 2,
        explanation: "Question Tag untuk ajakan yang dimulai dengan 'Let's' (Let us) selalu menggunakan 'shall we'."
    },
    {
        question: "Despite ______ tired, he kept working.",
        options: ["he is", "of being", "being", "be"],
        answer: 2,
        explanation: "'Despite' adalah preposisi yang langsung diikuti oleh Noun atau Gerund (V-ing). Tidak boleh ada 'of' setelah despite (itu milik 'in spite of'). Juga tidak boleh diikuti kalimat penuh (he is) tanpa kata sambung lain."
    },
    {
        question: "I have ______ friends in this city, so I'm lonely.",
        options: ["a few", "few", "little", "a little"],
        answer: 1,
        explanation: "'Friends' bisa dihitung (countable). 'A few' artinya sedikit tapi cukup (positif). 'Few' artinya sangat sedikit/hampir tidak ada (negatif). Karena dia merasa kesepian (lonely), berarti temannya sangat sedikit, jadi 'few'."
    },
    {
        question: "The teacher had the students ______ the essay.",
        options: ["write", "to write", "writing", "written"],
        answer: 0,
        explanation: "Causative 'Have': Have + Person + V1 (Base Form). Artinya menyuruh/meminta seseorang melakukan sesuatu. Beda dengan 'Get' + Person + 'to' + V1."
    },
    {
        question: "He speaks as if he ______ the boss.",
        options: ["is", "was", "were", "has been"],
        answer: 2,
        explanation: "'As if' (seolah-olah) mengindikasikan situasi yang tidak nyata. Seperti Conditional Type 2, kita menggunakan 'were' untuk semua subjek."
    },
    {
        question: "Seldom ______ such a beautiful sunset.",
        options: ["I have seen", "have I seen", "I saw", "seen I"],
        answer: 1,
        explanation: "Kata 'Seldom' (jarang) adalah adverb bermakna negatif. Jika diletakkan di awal kalimat untuk penekanan, wajib menggunakan Inversi: Auxiliary (have) + Subjek (I) + Verb."
    },
    {
        question: "You ______ pay for the ticket; it's free.",
        options: ["must not", "don't have to", "should not", "could not"],
        answer: 1,
        explanation: "'Must not' adalah larangan. 'Don't have to' adalah ketidakharusan (tidak perlu). Karena gratis, kamu 'tidak perlu' bayar, bukan 'dilarang' bayar."
    },
    {
        question: "I wish I ______ harder for the exam yesterday.",
        options: ["studied", "had studied", "would study", "study"],
        answer: 1,
        explanation: "Menyatakan penyesalan tentang masa lalu (yesterday). Gunakan 'Past Perfect' (had + V3) setelah 'wish' untuk kejadian lampau."
    },
    {
        question: "______ the bad weather, the flight was cancelled.",
        options: ["Because", "Due to", "Since", "As"],
        answer: 1,
        explanation: "'Because', 'Since', dan 'As' diikuti oleh klausa (Subject + Verb). 'Due to' berfungsi sebagai preposisi yang diikuti oleh Noun Phrase ('the bad weather')."
    },
    {
        question: "The more you practice, ______ you become.",
        options: ["the better", "better", "the best", "good"],
        answer: 0,
        explanation: "Ini adalah 'Double Comparative'. Polanya: The + comparative, the + comparative. Artinya semakin... semakin... (Semakin berlatih, semakin baik jadinya)."
    },
    {
        question: "I am looking forward to ______ you.",
        options: ["see", "seeing", "saw", "be seen"],
        answer: 1,
        explanation: "Dalam frasa 'look forward to', kata 'to' adalah preposisi, bukan bagian dari infinitive. Preposisi selalu diikuti oleh Gerund (V-ing). Jadi 'seeing', bukan 'see'."
    },
    {
        question: "Having ______ the work, he went home.",
        options: ["finish", "finished", "finishing", "finishes"],
        answer: 1,
        explanation: "Ini adalah 'Perfect Participle' (Having + V3). Digunakan untuk menekankan bahwa satu aksi telah selesai sepenuhnya sebelum aksi berikutnya dimulai."
    },
    {
        question: "Did you get your hair ______?",
        options: ["cut", "cutting", "to cut", "cutted"],
        answer: 0,
        explanation: "Causative Passive: Get + Object (benda) + V3. Artinya meminta orang lain melakukan sesuatu pada benda tersebut. V3 dari 'cut' tetap 'cut'."
    },
    {
        question: "Don't forget to call me, ______?",
        options: ["will you", "do you", "don't you", "won't you"],
        answer: 0,
        explanation: "Untuk kalimat perintah (Imperative), question tag-nya biasanya 'will you'. Apalagi untuk perintah negatif (Don't...), tag-nya menjadi positif 'will you'."
    },
    {
        question: "I can't afford ______ a new car.",
        options: ["buying", "to buy", "buy", "bought"],
        answer: 1,
        explanation: "Kata kerja 'afford' selalu diikuti oleh 'To Infinitive' (to + V1). Tidak bisa diikuti V-ing."
    },
    {
        question: "Is this the book ______ you were looking for?",
        options: ["who", "what", "where", "that"],
        answer: 3,
        explanation: "Untuk benda (book), kita menggunakan 'which' atau 'that'. 'Who' untuk orang, 'Where' untuk tempat, 'What' tidak digunakan sebagai relative pronoun penghubung noun."
    },
    {
        question: "Nobody called, ______?",
        options: ["did he", "didn't he", "did they", "didn't they"],
        answer: 2,
        explanation: "'Nobody' dianggap tunggal secara gramatikal, TAPI dalam Question Tag, kata gantinya menjadi 'they'. Karena 'nobody' bermakna negatif, tag-nya harus positif. Jadi 'did they'."
    },
    {
        question: "She accused him ______ stealing the money.",
        options: ["of", "for", "on", "about"],
        answer: 0,
        explanation: "Pasangan tetap (collocation) untuk kata 'accuse' adalah preposisi 'of'. Accuse someone OF doing something."
    },
    {
        question: "______ rains, we will stay at home.",
        options: ["Unless it", "If it", "Provided", "Had it"],
        answer: 1,
        explanation: "Kalimat ini sederhana: Jika hujan, kita diam di rumah. 'Unless' berarti 'Jika tidak', yang akan membuat maknanya aneh (Jika tidak hujan, kita diam di rumah?). Jadi 'If it' adalah jawaban yang benar."
    },
    {
        question: "Thinking that he had made a mistake, ______.",
        options: ["the apology was sent", "he apologized", "an apology came", "it was apologized"],
        answer: 1,
        explanation: "Ini adalah masalah 'Dangling Modifier'. Bagian depan kalimat ('Thinking that...') merujuk pada subjek yang melakukan aksi berpikir. Subjek kalimat utama haruslah orang yang berpikir itu ('He'). Opsi lain membuat seolah-olah 'permintaan maaf' yang berpikir."
    },
    {
        question: "I wasn't used to ______ on the left side of the road.",
        options: ["drive", "driving", "drove", "driven"],
        answer: 1,
        explanation: "'Wasn't used to' (dulu tidak terbiasa) diikuti oleh Gerund (V-ing) atau Noun. Ini tentang kebiasaan/familiaritas, bukan 'used to' (dulu sering) yang diikuti V1."
    },
    {
        question: "Five years ______ a long time to wait.",
        options: ["is", "are", "were", "have been"],
        answer: 0,
        explanation: "Frasa waktu, uang, dan jarak (seperti 'Five years') dianggap sebagai satu kesatuan tunggal (singular unit). Jadi kita menggunakan verb tunggal 'is'."
    },
    {
        question: "Before ______ out, please turn off the lights.",
        options: ["go", "going", "gone", "you will go"],
        answer: 1,
        explanation: "Setelah preposisi (Before), jika tidak ada subjek, kita langsung menggunakan Gerund (V-ing)."
    },
    {
        question: "______ English, he also speaks Spanish.",
        options: ["In addition", "Beside", "Besides", "Moreover"],
        answer: 2,
        explanation: "'Beside' (tanpa s) artinya di sebelah. 'Besides' (pakai s) artinya 'di samping itu' atau 'selain'. Konteks kalimat ini adalah 'Selain bahasa Inggris...'."
    },
    {
        question: "Why did you refuse ______ the offer?",
        options: ["accepting", "to accept", "accept", "accepted"],
        answer: 1,
        explanation: "Kata kerja 'refuse' (menolak) diikuti oleh 'To Infinitive'. Polanya: refuse to do something."
    },
    {
        question: "The fast food restaurant is ______ the bank and the post office.",
        options: ["among", "between", "through", "along"],
        answer: 1,
        explanation: "'Between' digunakan saat benda berada di antara dua titik spesifik/terpisah. 'Among' digunakan jika berada di antara banyak hal (lebih dari dua) yang tidak spesifik."
    },
    {
        question: "He is ______ honest man.",
        options: ["a", "an", "the", "-"],
        answer: 1,
        explanation: "Meskipun 'honest' dimulai dengan huruf 'h', huruf itu tidak dibunyikan (silent h). Pengucapannya dimulai dengan bunyi vokal 'o'. Oleh karena itu, kita menggunakan artikel 'an'."
    },
    {
        question: "We should avoid ______ during rush hour.",
        options: ["leave", "to leave", "leaving", "left"],
        answer: 2,
        explanation: "Sama seperti soal sebelumnya, kata kerja 'avoid' wajib diikuti Gerund (V-ing)."
    },
    {
        question: "There is no point in ______ about it.",
        options: ["worry", "to worry", "worrying", "worried"],
        answer: 2,
        explanation: "Frasa 'There is no point in' (tidak ada gunanya...) selalu diikuti V-ing."
    },
    {
        question: "Either John or his parents ______ going to the meeting.",
        options: ["is", "are", "was", "has"],
        answer: 1,
        explanation: "Dalam struktur 'Either... or...', kata kerja mengikuti subjek yang *paling dekat* dengannya. Subjek terdekat adalah 'his parents' (jamak), jadi gunakan 'are'."
    },
    {
        question: "Had I known it was your birthday, I ______ bought a gift.",
        options: ["will have", "would have", "would", "had"],
        answer: 1,
        explanation: "Inversi Conditional Type 3. Struktur lengkapnya: 'If I had known..., I would have bought...'. Kita menghilangkan 'If' dan membalik menjadi 'Had I known'. Klausa utama tetap 'would have + V3'."
    },
    {
        question: "It was ______ cold that I wore two jackets.",
        options: ["so", "such", "very", "too"],
        answer: 0,
        explanation: "Gunakan 'so' jika diikuti langsung oleh Adjective (so cold). Gunakan 'such' jika diikuti Noun Phrase (such a cold day). Pola: So + Adj + that..."
    },
    {
        question: "I ______ waiting for two hours when he finally arrived.",
        options: ["have been", "had been", "was", "am"],
        answer: 1,
        explanation: "Past Perfect Continuous. Kita menekankan durasi (for two hours) yang terjadi di masa lalu *sebelum* kejadian masa lalu lain (he arrived). 'Have been' salah karena itu untuk koneksi ke masa kini."
    },
    {
        question: "Would you mind if I ______ the window?",
        options: ["open", "opened", "opening", "opens"],
        answer: 1,
        explanation: "Frasa 'Would you mind IF...' diperlakukan seperti Conditional Type 2 (situasi hipotetis/sopan santun). Jadi, kata kerjanya harus bentuk Past Tense ('opened'), meskipun kejadiannya sekarang."
    },
    {
        question: "The news ______ shocking.",
        options: ["were", "was", "are", "have been"],
        answer: 1,
        explanation: "Kata 'news' meskipun berakhiran 's', adalah Uncountable Noun (tidak bisa dihitung) dan selalu dianggap tunggal. Jadi gunakan 'was'."
    },
    {
        question: "Where did you get that dress ______?",
        options: ["make", "made", "making", "to make"],
        answer: 1,
        explanation: "Causative Get (Passive): Get + Object + V3. 'Where did you get that dress made?' artinya 'Di mana kamu menyuruh orang membuat gaun itu?' (Di mana kamu menjahitkan gaun itu?)."
    },
    {
        question: "I'm looking forward to ______ on holiday next week.",
        options: ["go", "going", "gone", "went"],
        answer: 1,
        explanation: "Jebakan umum! Meskipun ada kata 'to', dalam frasa 'look forward to', kata 'to' adalah preposisi. Setelah preposisi, kata kerja wajib berbentuk Gerund (V-ing). Jadi, 'going' adalah jawaban yang benar."
    },
    {
        question: "There is no point ______ for him. He won't come.",
        options: ["in waiting", "to wait", "wait", "for waiting"],
        answer: 0,
        explanation: "Idiom 'There is no point' biasanya diikuti oleh preposisi 'in' + Gerund (V-ing). Kadang 'in' dihilangkan, tapi tetap diikuti V-ing (waiting)."
    },
    {
        question: "______ I known you were in town, I would have visited you.",
        options: ["If", "Had", "Have", "Should"],
        answer: 1,
        explanation: "Ini adalah Inversi dari Conditional Sentence Type 3. Bentuk aslinya: 'If I had known...'. Jika 'If' dihilangkan, posisi 'Had' dan subjek ditukar menjadi 'Had I known...'. Maknanya sama: penyesalan masa lalu."
    },
    {
        question: "The scissors ______ on the table.",
        options: ["is", "are", "was", "has"],
        answer: 1,
        explanation: "Benda yang terdiri dari dua bagian berpasangan (scissors, glasses, pants, trousers) selalu dianggap jamak (plural). Jadi gunakan 'are'."
    },
    {
        question: "She made me ______ the whole house.",
        options: ["clean", "to clean", "cleaning", "cleaned"],
        answer: 0,
        explanation: "Causative Verbs: 'Make' + Person + V1 (Bare Infinitive). Artinya memaksa seseorang melakukan sesuatu. Jangan gunakan 'to' setelah 'make'."
    },
    {
        question: "I'd better ______ now or I'll be late.",
        options: ["to leave", "leave", "leaving", "left"],
        answer: 1,
        explanation: "Frasa 'Had better' ('d better) berfungsi seperti modal (seperti 'should'). Jadi harus diikuti V1 murni tanpa 'to'."
    },
    {
        question: "Not only ______ late, but she also forgot her books.",
        options: ["she was", "was she", "she is", "is she"],
        answer: 1,
        explanation: "Inversi! Jika kalimat dimulai dengan 'Not only', susunan subjek dan to be/auxiliary harus dibalik. Karena konteksnya masa lalu (forgot), gunakan 'was she'."
    },
    {
        question: "It's about time you ______ to bed.",
        options: ["go", "went", "gone", "have gone"],
        answer: 1,
        explanation: "Setelah frasa 'It's time' atau 'It's about time', kita menggunakan Past Tense untuk menyatakan bahwa sesuatu seharusnya sudah dilakukan sekarang (urgensi). Jadi 'went'."
    },
    {
        question: "Neither of the answers ______ correct.",
        options: ["is", "are", "were", "have"],
        answer: 0,
        explanation: "'Neither of' merujuk pada 'tidak satu pun dari keduanya'. Secara gramatikal formal, ini dianggap tunggal (singular). Jadi gunakan 'is'."
    },
    {
        question: "I prefer coffee ______ tea.",
        options: ["than", "to", "from", "over"],
        answer: 1,
        explanation: "Pola 'Prefer': Prefer A to B. Jangan gunakan 'than' (kecuali pakai 'would rather'). Contoh: I prefer swimming to running."
    },
    {
        question: "Do you mind ______ the window?",
        options: ["open", "to open", "opening", "opened"],
        answer: 2,
        explanation: "Frasa sopan 'Do you mind' atau 'Would you mind' selalu diikuti Gerund (V-ing)."
    },
    {
        question: "Unless you ______ now, you will miss the bus.",
        options: ["start", "don't start", "will start", "started"],
        answer: 0,
        explanation: "'Unless' artinya 'If... not' (kecuali jika). Kalimatnya sudah mengandung makna negatif, jadi tidak perlu 'don't' lagi. Gunakan Present Simple untuk masa depan."
    },
    {
        question: "I wish I ______ rich.",
        options: ["am", "was", "were", "will be"],
        answer: 2,
        explanation: "Subjunctive Mood (Pengandaian). Untuk harapan yang tidak nyata saat ini, 'to be' untuk semua subjek adalah 'were'."
    },
    {
        question: "He is used to ______ up early.",
        options: ["get", "getting", "got", "gotten"],
        answer: 1,
        explanation: "Perhatikan 'is used to' (ada to be-nya). Ini artinya 'terbiasa' (sudah adaptasi). Diikuti V-ing. Beda dengan 'used to' (dulu pernah) yang diikuti V1."
    },
    {
        question: "The man to ______ I spoke was very kind.",
        options: ["who", "whom", "which", "that"],
        answer: 1,
        explanation: "Karena ada preposisi 'to' sebelum kata ganti, kita wajib menggunakan 'whom' untuk orang (objek). 'Who' tidak bisa dipakai langsung setelah preposisi."
    },
    {
        question: "Hardly had I arrived ______ the phone rang.",
        options: ["when", "than", "after", "while"],
        answer: 0,
        explanation: "Pasangan kata (Correlative Conjunction): 'Hardly... when...' atau 'Scarcely... when...'. Artinya: Baru saja sampai, tiba-tiba telepon berbunyi."
    },
    {
        question: "We stopped ______ some water because we were thirsty.",
        options: ["to drink", "drinking", "drink", "drank"],
        answer: 0,
        explanation: "'Stop to drink' = Berhenti melakukan aktivitas lain *agar bisa* minum. 'Stop drinking' = Berhenti minum (selamanya/saat itu). Karena haus, mereka berhenti *untuk* minum."
    },
    {
        question: "______ rains, we will cancel the trip.",
        options: ["If it", "Unless it", "Whether it", "Provided"],
        answer: 0,
        explanation: "Logika sederhana: Jika hujan, batal. 'Unless' akan membuat arti terbalik (Kecuali hujan, batal? Aneh)."
    },
    {
        question: "My father suggests that I ______ hard.",
        options: ["study", "studies", "studied", "studying"],
        answer: 0,
        explanation: "Subjunctive setelah 'suggest that'. Kata kerja kembali ke bentuk dasar (base form) tanpa 's'/'es', bahkan untuk subjek 'I/He/She'."
    },
    {
        question: "I remember ______ my keys on the table, but they are gone.",
        options: ["put", "to put", "putting", "puts"],
        answer: 2,
        explanation: "Ingat kejadian masa lalu (memori) = Remember + V-ing. Ingat tugas yang harus dilakukan = Remember + To V1. Di sini dia ingat *telah* menaruhnya."
    },
    {
        question: "This is the first time I ______ sushi.",
        options: ["eat", "ate", "have eaten", "eating"],
        answer: 2,
        explanation: "Pola 'It is the first/second time...' wajib diikuti Present Perfect Tense (have/has + V3)."
    },
    {
        question: "Suppose you ______ the lottery, what would you do?",
        options: ["win", "won", "have won", "will win"],
        answer: 1,
        explanation: "'Suppose' di sini berfungsi seperti 'If' dalam Conditional Type 2 (khayalan). Jadi diikuti Past Tense (won)."
    },
    {
        question: "Don't forget to lock the door, ______?",
        options: ["will you", "do you", "don't you", "shall we"],
        answer: 0,
        explanation: "Imperative (kalimat perintah/larangan) biasanya menggunakan tag 'will you'. Khusus 'Let's' pakai 'shall we'."
    },
    {
        question: "She kept on ______ although she was tired.",
        options: ["work", "to work", "working", "worked"],
        answer: 2,
        explanation: "Frasa 'keep on' (terus menerus) diikuti Gerund (V-ing)."
    },
    {
        question: "Usually, I work at the office, but today I ______ from home.",
        options: ["work", "am working", "worked", "have worked"],
        answer: 1,
        explanation: "Perbedaan Present Simple (kebiasaan: usually) dan Present Continuous (sementara hari ini: today). Untuk 'today', gunakan 'am working'."
    },
    {
        question: "By next year, they ______ the bridge.",
        options: ["will finish", "will have finished", "finish", "are finishing"],
        answer: 1,
        explanation: "Future Perfect Tense. Ada kata kunci 'By...' (menjelang). Artinya pada saat itu di masa depan, jembatan *sudah akan* selesai dibangun."
    },
    {
        question: "No sooner had he arrived ______ the train left.",
        options: ["when", "than", "before", "after"],
        answer: 1,
        explanation: "Pasangan tetap: 'No sooner... than...'. (Bedakan dengan Hardly... when...)."
    },
    {
        question: "Every student ______ to submit the assignment.",
        options: ["have", "has", "are", "having"],
        answer: 1,
        explanation: "'Every' selalu dianggap tunggal (singular). Jadi gunakan 'has' (atau verb+s)."
    },
    {
        question: "I tried ______ the window, but it was stuck.",
        options: ["open", "to open", "opening", "opened"],
        answer: 1,
        explanation: "'Try to open' = Berusaha dengan keras (effort). 'Try opening' = Mencoba metode baru/eksperimen. Karena macet (stuck), berarti dia berusaha keras, jadi 'try to'."
    },
    {
        question: "I will call you when I ______ there.",
        options: ["get", "will get", "got", "getting"],
        answer: 0,
        explanation: "Time Clause (when, as soon as, before). Jangan gunakan 'will' setelah kata hubung waktu ini, meskipun maknanya masa depan. Gunakan Present Simple."
    },
    {
        question: "She is one of the students who ______ always late.",
        options: ["is", "are", "was", "be"],
        answer: 1,
        explanation: "Jebakan Subject-Verb Agreement. 'Who' merujuk pada 'students' (jamak), bukan 'one'. Jadi: Dia adalah salah satu dari *siswa-siswa* yang (mereka) selalu terlambat."
    },
    {
        question: "Let ______ go!",
        options: ["we", "us", "our", "ours"],
        answer: 1,
        explanation: "'Let' diikuti objek pronoun. Bentuk objek dari 'we' adalah 'us'."
    },
    {
        question: "Can you tell me where ______?",
        options: ["is the post office", "the post office is", "the post office", "is it"],
        answer: 1,
        explanation: "Indirect Question. Urutan kata kembali normal (Subjek + Verb), tidak dibalik. Jadi: 'where the post office is'."
    },
    {
        question: "Would you rather I ______?",
        options: ["leave", "left", "leaving", "gone"],
        answer: 1,
        explanation: "'Would rather' diikuti subjek orang lain (I) menuntut bentuk Past Tense (Subjunctive) untuk keinginan saat ini. Jadi 'left'."
    },
    {
        question: "Nobody acts like that, ______?",
        options: ["do they", "don't they", "does he", "doesn't he"],
        answer: 0,
        explanation: "'Nobody' bermakna negatif, jadi tag-nya positif. Kata ganti 'nobody' dalam tag adalah 'they'. Jadi: 'do they'."
    },
    {
        question: "It was ______ a boring film that I fell asleep.",
        options: ["so", "such", "very", "too"],
        answer: 1,
        explanation: "'Such' digunakan sebelum Noun Phrase (a ... film). 'So' hanya untuk Adjective. Pola: Such + a/an + adj + noun."
    },
    {
        question: "Did you get your car ______?",
        options: ["fix", "fixing", "fixed", "to fix"],
        answer: 2,
        explanation: "Passive Causative: Get + Object + V3. Artinya mobilnya diperbaiki oleh orang lain."
    },
    {
        question: "______ being rich, he is very unhappy.",
        options: ["Although", "Despite", "Even though", "However"],
        answer: 1,
        explanation: "'Despite' diikuti Gerund (being). 'Although' harus diikuti kalimat lengkap (he is rich)."
    },
    {
        question: "I need ______ information about the course.",
        options: ["some", "an", "many", "few"],
        answer: 0,
        explanation: "'Information' adalah Uncountable Noun (tidak bisa dihitung). Tidak bisa pakai 'an', 'many', atau 'few'. Gunakan 'some'."
    },
    {
        question: "My mother made me ______ my vegetables.",
        options: ["eat", "to eat", "eating", "ate"],
        answer: 0,
        explanation: "Causative 'Make' + Object + Bare Infinitive (V1). Tanpa 'to'. Jadi 'make me eat'."
    },
    {
        question: "If I ______ you, I wouldn't do that.",
        options: ["was", "were", "am", "have been"],
        answer: 1,
        explanation: "Conditional Type 2. Selalu gunakan 'were' untuk semua subjek dalam pengandaian formal."
    },
    {
        question: "The police ______ looking for the suspect.",
        options: ["is", "are", "was", "has"],
        answer: 1,
        explanation: "Kata benda 'Police' selalu jamak (plural). Gunakan 'are'."
    },
    {
        question: "She asked me if I ______ help her.",
        options: ["can", "could", "will", "may"],
        answer: 1,
        explanation: "Reported Speech (Kalimat tidak langsung). 'Can' berubah menjadi bentuk lampau 'Could'."
    },
    {
        question: "I apologize ______ being late.",
        options: ["for", "to", "at", "on"],
        answer: 0,
        explanation: "Pasangan preposisi: Apologize TO someone FOR something (doing something). Di sini alasannya, jadi 'for'."
    },
    {
        question: "They have lived here ______ 2010.",
        options: ["since", "for", "in", "during"],
        answer: 0,
        explanation: "'Since' untuk titik awal waktu (tahun, tanggal). 'For' untuk durasi (jumlah tahun)."
    },
    {
        question: "You ______ smoke in the hospital area.",
        options: ["don't have to", "must not", "might not", "need not"],
        answer: 1,
        explanation: "Larangan keras (Prohibition). Gunakan 'must not'."
    },
    {
        question: "I saw him ______ the street.",
        options: ["cross", "to cross", "crossed", "crosses"],
        answer: 0,
        explanation: "Verbs of perception (see, hear, watch) bisa diikuti V1 (melihat seluruh kejadian) atau V-ing (melihat sebagian proses). 'To cross' salah. Di sini opsi yang tersedia dan benar adalah 'cross' (V1)."
    },
    {
        question: "Whose book is this? It's ______.",
        options: ["my", "mine", "me", "I"],
        answer: 1,
        explanation: "Possessive Pronoun (Kata ganti kepemilikan) yang berdiri sendiri tanpa kata benda di belakangnya adalah 'mine'. ('My' harus diikuti benda: My book)."
    },
    {
        question: "Physics ______ my favorite subject.",
        options: ["is", "are", "were", "have"],
        answer: 0,
        explanation: "Nama mata pelajaran (Physics, Mathematics, Economics) berakhiran 's' tapi tunggal. Gunakan 'is'."
    },
    {
        question: "Had I known the answer, I ______ told you.",
        options: ["would", "will have", "would have", "had"],
        answer: 2,
        explanation: "Conditional Type 3. Bagian hasil (result clause) wajib menggunakan 'would have + V3'."
    },
    {
        question: "The price of oil has ______ significantly.",
        options: ["raised", "risen", "rose", "raising"],
        answer: 1,
        explanation: "Bedakan 'Rise' dan 'Raise'. 'Rise' (V2: Rose, V3: Risen) adalah intransitive (tidak butuh objek), artinya naik sendiri. 'Raise' butuh objek (menaikkan sesuatu). Karena harga minyak naik sendiri (tidak ada objek setelahnya), gunakan V3 dari Rise: 'risen'."
    },
    {
        question: "Please ______ your hand if you have a question.",
        options: ["rise", "raise", "arise", "rose"],
        answer: 1,
        explanation: "Kebalikan dari soal sebelumnya. Di sini ada objek 'your hand'. Jadi kita butuh kata kerja transitif 'raise' (mengangkat/menaikkan)."
    },
    {
        question: "She is the woman ______ husband is a famous actor.",
        options: ["who", "whom", "which", "whose"],
        answer: 3,
        explanation: "Relative Pronoun untuk kepemilikan (possession). 'Whose husband' artinya 'suami milik wanita itu'."
    },
    {
        question: "I can't find my keys. I ______ them in the car.",
        options: ["must leave", "must have left", "should leave", "had to leave"],
        answer: 1,
        explanation: "Modal Perfect (Must have + V3) digunakan untuk kesimpulan logika yang kuat tentang masa lalu (Past Deduction). 'Pasti saya tertinggal di mobil'."
    },
    {
        question: "You ______ told me earlier! Now it's too late.",
        options: ["must have", "should have", "would have", "could"],
        answer: 1,
        explanation: "Modal Perfect (Should have + V3) digunakan untuk penyesalan atau kritik tentang sesuatu yang *seharusnya* dilakukan di masa lalu tapi tidak dilakukan."
    },
    {
        question: "The heavy rain prevented us ______ going out.",
        options: ["to", "from", "for", "of"],
        answer: 1,
        explanation: "Pasangan kata (collocation): Prevent someone FROM doing something. Selalu gunakan 'from' setelah prevent."
    },
    {
        question: "He is interested ______ learning Japanese.",
        options: ["on", "at", "in", "with"],
        answer: 2,
        explanation: "Adjective 'interested' selalu berpasangan dengan preposisi 'in'."
    },
    {
        question: "______ strictly speaking, spiders are arachnids.",
        options: ["To", "From", "By", "-"],
        answer: 3,
        explanation: "Frasa 'Strictly speaking' (secara harfiah/ketat) sudah lengkap dan tidak membutuhkan preposisi tambahan di depannya."
    },
    {
        question: "The number of students in the class ______ twenty.",
        options: ["is", "are", "be", "were"],
        answer: 0,
        explanation: "Peraturan penting: 'The number of...' (jumlah dari...) dianggap TUNGGAL (Singular), jadi pakai 'is'. Sedangkan 'A number of...' (sejumlah/banyak) dianggap JAMAK (Plural)."
    },
    {
        question: "A number of students ______ waiting outside.",
        options: ["is", "are", "was", "has"],
        answer: 1,
        explanation: "Seperti penjelasan sebelumnya, 'A number of' bermakna 'banyak/beberapa', sehingga kata kerjanya jamak ('are')."
    },
    {
        question: "Hardly ______ entered the room when the lights went out.",
        options: ["did I", "have I", "had I", "I had"],
        answer: 2,
        explanation: "Inversi dengan 'Hardly'. Urutan waktunya: Masuk dulu (kejadian 1), baru lampu mati (kejadian 2). Kejadian 1 menggunakan Past Perfect Inversion: 'had I entered'."
    },
    {
        question: "It is worth ______ that book.",
        options: ["read", "to read", "reading", "readed"],
        answer: 2,
        explanation: "Setelah ekspresi 'It is worth' (layak untuk...), kita wajib menggunakan Gerund (V-ing)."
    },
    {
        question: "I object to ______ treated like this.",
        options: ["be", "being", "been", "to be"],
        answer: 1,
        explanation: "Dalam frasa 'object to' (keberatan terhadap), kata 'to' adalah preposisi. Jadi harus diikuti V-ing. Karena pasif (diperlakukan), jadinya 'being treated'."
    },
    {
        question: "He ran fast ______ catch the bus.",
        options: ["enough to", "too to", "so that", "in order"],
        answer: 0,
        explanation: "Pola 'Adjective/Adverb + enough + to Infinitive'. Dia berlari *cukup cepat untuk* mengejar bus."
    },
    {
        question: "The meeting was called ______ due to illness.",
        options: ["in", "off", "out", "up"],
        answer: 1,
        explanation: "Phrasal Verb: 'Call off' artinya membatalkan (cancel). 'Call in' memanggil, 'Call up' menelepon."
    },
    {
        question: "Please put ______ your cigarette.",
        options: ["out", "off", "away", "in"],
        answer: 0,
        explanation: "Phrasal Verb: 'Put out' artinya memadamkan (api/rokok). 'Put off' artinya menunda."
    },
    {
        question: "I look forward to ______ from you.",
        options: ["hear", "hearing", "heard", "hears"],
        answer: 1,
        explanation: "Pengulangan konsep penting: 'Look forward to' + V-ing."
    },
    {
        question: "Not only ______ intelligent, but she is also funny.",
        options: ["she is", "is she", "she was", "was she"],
        answer: 1,
        explanation: "Inversi setelah 'Not only'. Karena kalimat kedua pakai 'is' (Present), maka depannya juga Present: 'is she'."
    },
    {
        question: "Little ______ that he was a spy.",
        options: ["I knew", "did I know", "do I know", "I know"],
        answer: 1,
        explanation: "Inversi dengan kata negatif 'Little' di awal kalimat. Karena konteks cerita (was), gunakan auxiliary lampau 'did'. Pola: Little + did + Subject + V1."
    },
    {
        question: "Suppose you ______ a million dollars, what would you buy?",
        options: ["win", "won", "had won", "winning"],
        answer: 1,
        explanation: "'Suppose' = 'If'. Ini Conditional Type 2 (khayalan). Gunakan V2 (Past Simple)."
    },
    {
        question: "I wish you ______ stop making that noise.",
        options: ["will", "would", "can", "could"],
        answer: 1,
        explanation: "Gunakan 'wish + would' ketika kita merasa terganggu (annoyed) dan ingin seseorang mengubah perilakunya."
    },
    {
        question: "It's time we ______ home.",
        options: ["go", "went", "gone", "going"],
        answer: 1,
        explanation: "Setelah 'It's time', gunakan Past Simple (went) untuk menyuruh sekarang."
    },
    {
        question: "I'd rather you ______ smoke inside.",
        options: ["don't", "didn't", "won't", "not"],
        answer: 1,
        explanation: "'Would rather' + orang lain + Past Tense. (Aku lebih suka kamu tidak merokok)."
    },
    {
        question: "If I hadn't missed the bus, I ______ here now.",
        options: ["would be", "would have been", "will be", "am"],
        answer: 0,
        explanation: "Mixed Conditional! Bagian 'If' adalah masa lalu (Type 3: hadn't missed), tapi hasilnya dirasakan SEKARANG (now). Jadi hasilnya pakai Type 2 (would + V1), bukan 'would have been'."
    },
    {
        question: "______ I known the truth, I wouldn't have helped him.",
        options: ["If", "Had", "Have", "Should"],
        answer: 1,
        explanation: "Inversi Conditional Type 3. (Had I known... = If I had known...)."
    },
    {
        question: "Under no circumstances ______ open this door.",
        options: ["you should", "should you", "you must", "must you"],
        answer: 1,
        explanation: "Frasa negatif 'Under no circumstances' di awal kalimat mewajibkan Inversi. (Should you open...)."
    },
    {
        question: "The man, ______ father is a professor, is my friend.",
        options: ["who", "whom", "whose", "which"],
        answer: 2,
        explanation: "Kepemilikan: Ayah milik pria itu. Gunakan 'whose'."
    },
    {
        question: "Is she used to ______ alone?",
        options: ["live", "living", "lived", "lives"],
        answer: 1,
        explanation: "'Be used to' (Terbiasa) + V-ing."
    },
    {
        question: "I used to ______ in London.",
        options: ["live", "living", "lived", "lives"],
        answer: 0,
        explanation: "'Used to' (Dulu pernah) + V1 (Base form). Tanpa 'be' di depannya."
    },
    {
        question: "The scissors ______ dull.",
        options: ["is", "are", "was", "has"],
        answer: 1,
        explanation: "Scissors (gunting) selalu jamak."
    },
    {
        question: "Mathematics ______ difficult for some students.",
        options: ["is", "are", "were", "have"],
        answer: 0,
        explanation: "Mathematics (ilmu) selalu tunggal meskipun akhiran 's'."
    },
    {
        question: "Neither John nor his friends ______ going.",
        options: ["is", "are", "was", "has"],
        answer: 1,
        explanation: "Subject-Verb Agreement 'Neither... nor...'. Ikuti subjek terdekat (his friends = jamak)."
    },
    {
        question: "Either the teacher or the student ______ to blame.",
        options: ["is", "are", "were", "have"],
        answer: 0,
        explanation: "Ikuti subjek terdekat (the student = tunggal)."
    },
    {
        question: "Five miles ______ a long distance to walk.",
        options: ["is", "are", "were", "have"],
        answer: 0,
        explanation: "Jarak (distance), Uang (money), Waktu (time) dianggap satu kesatuan unit tunggal."
    },
    {
        question: "There ______ a book and two pens on the table.",
        options: ["is", "are", "were", "have"],
        answer: 0,
        explanation: "Jika menggunakan 'There is/are', ikuti kata benda PERTAMA yang muncul. Karena 'a book' tunggal, gunakan 'is'. (Meskipun total bendanya banyak)."
    },
    {
        question: "The police ______ arrested the thief.",
        options: ["has", "have", "is", "was"],
        answer: 1,
        explanation: "Police = Jamak (Plural). Gunakan 'have'."
    },
    {
        question: "I prefer walking ______ driving.",
        options: ["than", "to", "from", "over"],
        answer: 1,
        explanation: "Prefer A TO B."
    },
    {
        question: "I would rather walk ______ drive.",
        options: ["than", "to", "from", "then"],
        answer: 0,
        explanation: "Would rather A THAN B."
    },
    {
        question: "It is high time you ______ a job.",
        options: ["find", "found", "finding", "will find"],
        answer: 1,
        explanation: "'It is high time' + Past Tense."
    },
    {
        question: "He acts as if he ______ the boss.",
        options: ["is", "was", "were", "has been"],
        answer: 2,
        explanation: "'As if' (seolah-olah) = Unreal. Gunakan 'were' untuk semua subjek."
    },
    {
        question: "I will call you as soon as I ______.",
        options: ["arrive", "will arrive", "arrived", "am arriving"],
        answer: 0,
        explanation: "Jangan pakai 'will' setelah 'as soon as' untuk masa depan. Pakai Present Simple."
    },
    {
        question: "Unless it ______, we will go.",
        options: ["rains", "doesn't rain", "will rain", "rained"],
        answer: 0,
        explanation: "Unless = If not. Jadi jangan didobel negatifnya. 'Unless it rains' (Kecuali jika hujan)."
    },
    {
        question: "The car needs ______.",
        options: ["wash", "washing", "to wash", "washed"],
        answer: 1,
        explanation: "Need + V-ing mempunyai arti pasif (perlu dicuci). Sama dengan 'needs to be washed'."
    },
    {
        question: "She admitted ______ the money.",
        options: ["steal", "to steal", "stealing", "stole"],
        answer: 2,
        explanation: "Verb 'admit' (mengakui) diikuti oleh Gerund (V-ing)."
    },
    {
        question: "He succeeded ______ solving the problem.",
        options: ["in", "on", "at", "to"],
        answer: 0,
        explanation: "Pasangan kata: Succeed IN doing something."
    },
    {
        question: "She is capable ______ doing it herself.",
        options: ["of", "in", "at", "to"],
        answer: 0,
        explanation: "Pasangan kata: Capable OF doing something."
    },
    {
        question: "I am afraid ______ spiders.",
        options: ["of", "at", "in", "to"],
        answer: 0,
        explanation: "Pasangan kata: Afraid OF something."
    },
    {
        question: "It was ______ a nice day that we went out.",
        options: ["so", "such", "very", "too"],
        answer: 1,
        explanation: "Such + a/an + Adjective + Noun."
    },
    {
        question: "The food was ______ good that I ate it all.",
        options: ["so", "such", "very", "too"],
        answer: 0,
        explanation: "So + Adjective (tanpa noun)."
    },
    {
        question: "______ I help you with your bag?",
        options: ["Will", "Shall", "Do", "Have"],
        answer: 1,
        explanation: "Gunakan 'Shall' dengan subjek 'I' atau 'We' untuk menawarkan bantuan (Offer) secara sopan. 'Shall I...?'"
    }
];