const questionsSource = [
    // --- LEVEL: BEGINNER (20 Soal) ---
    // Fokus: Simple Present, Present Continuous, Simple Past, Simple Future

    {
        question: "If you ______ water to 100 degrees Celsius, it boils.",
        options: ["heat", "heated", "will heat", "would heat"],
        answer: 0,
        explanation: "Conditional Type 0"
    },
    {
        question: "If it rains tomorrow, I ______ at home.",
        options: ["stay", "stayed", "will stay", "would stay"],
        answer: 2,
        explanation: "Conditional Type 1"
    },
    {
        question: "If I ______ a bird, I would fly to you.",
        options: ["was", "is", "am", "were"],
        answer: 3,
        explanation: "Conditional Type 2"
    },
    {
        question: "If I ______ harder, I would have passed the exam.",
        options: ["study", "studied", "had studied", "have studied"],
        answer: 2,
        explanation: "Conditional Type 3"
    },
    {
        question: "Ice ______ if you heat it.",
        options: ["melt", "melts", "melted", "will melt"],
        answer: 1,
        explanation: "Conditional Type 0"
    },
    {
        question: "If she invites me, I ______ to the party.",
        options: ["go", "went", "will go", "would go"],
        answer: 2,
        explanation: "Conditional Type 1"
    },
    {
        question: "If I had a lot of money, I ______ a big house.",
        options: ["will buy", "would buy", "bought", "had bought"],
        answer: 1,
        explanation: "Conditional Type 2"
    },
    {
        question: "She would have been happy if you ______ her a gift.",
        options: ["give", "gave", "had given", "have given"],
        answer: 2,
        explanation: "Conditional Type 3"
    },
    {
        question: "When the sun goes down, it ______ dark.",
        options: ["get", "gets", "got", "getting"],
        answer: 1,
        explanation: "Conditional Type 0"
    },
    {
        question: "We will miss the bus if we ______ not hurry.",
        options: ["do", "did", "are", "will"],
        answer: 0,
        explanation: "Conditional Type 1"
    },
    {
        question: "If he ______ here, he would help us.",
        options: ["is", "was", "were", "been"],
        answer: 2,
        explanation: "Conditional Type 2"
    },
    {
        question: "If they had left earlier, they ______ the train.",
        options: ["would catch", "will catch", "caught", "would have caught"],
        answer: 3,
        explanation: "Conditional Type 3"
    },
    {
        question: "Plants die if they ______ water.",
        options: ["don't get", "didn't get", "won't get", "wouldn't get"],
        answer: 0,
        explanation: "Conditional Type 0"
    },
    {
        question: "If you ______ too much, you will get fat.",
        options: ["eat", "ate", "eaten", "eating"],
        answer: 0,
        explanation: "Conditional Type 1"
    },
    {
        question: "I would travel the world if I ______ rich.",
        options: ["am", "was", "were", "will be"],
        answer: 2,
        explanation: "Conditional Type 2"
    },

    // --- INTERMEDIATE LEVEL (16-40) ---
    {
        question: "Unless you ______ now, you will be late.",
        options: ["leave", "left", "leaving", "will leave"],
        answer: 0,
        explanation: "Conditional Type 1"
    },
    {
        question: "If I ______ his number, I would call him.",
        options: ["know", "knew", "known", "had known"],
        answer: 1,
        explanation: "Conditional Type 2"
    },
    {
        question: "If the weather ______ good yesterday, we would have gone for a picnic.",
        options: ["is", "was", "has been", "had been"],
        answer: 3,
        explanation: "Conditional Type 3"
    },
    {
        question: "Does the light turn on if you ______ the switch?",
        options: ["press", "pressed", "will press", "pressing"],
        answer: 0,
        explanation: "Conditional Type 0"
    },
    {
        question: "What ______ you do if you lose your job?",
        options: ["would", "will", "did", "do"],
        answer: 1,
        explanation: "Conditional Type 1"
    },
    {
        question: "I ______ that if I were you.",
        options: ["won't do", "wouldn't do", "didn't do", "don't do"],
        answer: 1,
        explanation: "Conditional Type 2"
    },
    {
        question: "If I hadn't eaten so much, I ______ sick.",
        options: ["won't feel", "wouldn't feel", "wouldn't have felt", "didn't feel"],
        answer: 2,
        explanation: "Conditional Type 3"
    },
    {
        question: "If you mix red and blue, you ______ purple.",
        options: ["got", "get", "will get", "would get"],
        answer: 1,
        explanation: "Conditional Type 0"
    },
    {
        question: "He ______ angry if you don't tell him the truth.",
        options: ["is", "will be", "was", "would be"],
        answer: 1,
        explanation: "Conditional Type 1"
    },
    {
        question: "Where would you live if you ______ anywhere in the world?",
        options: ["can live", "could live", "will live", "live"],
        answer: 1,
        explanation: "Conditional Type 2"
    },
    {
        question: "If she ______ the sign, she wouldn't have crashed.",
        options: ["saw", "see", "had seen", "has seen"],
        answer: 2,
        explanation: "Conditional Type 3"
    },
    {
        question: "If babies are hungry, they usually ______.",
        options: ["cry", "cried", "will cry", "crying"],
        answer: 0,
        explanation: "Conditional Type 0"
    },
    {
        question: "If it rains, we ______ the match.",
        options: ["cancel", "would cancel", "will cancel", "canceled"],
        answer: 2,
        explanation: "Conditional Type 1"
    },
    {
        question: "If I ______ the lottery, I would buy a yacht.",
        options: ["win", "won", "had won", "winning"],
        answer: 1,
        explanation: "Conditional Type 2"
    },
    {
        question: "You could have stayed with us if you ______.",
        options: ["wanted", "want", "had wanted", "have wanted"],
        answer: 2,
        explanation: "Conditional Type 3"
    },
    {
        question: "Snakes bite if they ______ scared.",
        options: ["are", "were", "will be", "had been"],
        answer: 0,
        explanation: "Conditional Type 0"
    },
    {
        question: "I will lend you the money provided you ______ it back next week.",
        options: ["pay", "paid", "will pay", "would pay"],
        answer: 0,
        explanation: "Conditional Type 1"
    },
    {
        question: "It would be nice if you ______ so much noise.",
        options: ["didn't make", "don't make", "wouldn't make", "won't make"],
        answer: 0,
        explanation: "Conditional Type 2"
    },
    {
        question: "If I had known you were in town, I ______ you.",
        options: ["would visit", "will visit", "would have visited", "visited"],
        answer: 2,
        explanation: "Conditional Type 3"
    },
    {
        question: "If I ______ time tonight, I will watch a movie.",
        options: ["have", "had", "will have", "would have"],
        answer: 0,
        explanation: "Conditional Type 1"
    },

    // --- EXPERT LEVEL (41-50) ---
    {
        question: "Had I known about the traffic, I ______ earlier.",
        options: ["would leave", "will leave", "would have left", "left"],
        answer: 2,
        explanation: "Conditional Type 3"
    },
    {
        question: "Were I in your position, I ______ the offer.",
        options: ["will accept", "would accept", "accepted", "accept"],
        answer: 1,
        explanation: "Conditional Type 2"
    },
    {
        question: "Should you see him, ______ him to call me.",
        options: ["tell", "told", "would tell", "telling"],
        answer: 0,
        explanation: "Conditional Type 1"
    },
    {
        question: "But for his help, we ______ the project on time.",
        options: ["wouldn't finish", "won't finish", "wouldn't have finished", "didn't finish"],
        answer: 2,
        explanation: "Conditional Type 3"
    },
    {
        question: "If I ______ to accept the job, I would need to move.",
        options: ["was", "were", "am", "have"],
        answer: 1,
        explanation: "Conditional Type 2"
    },
    {
        question: "Had it not been for the rain, the event ______ a success.",
        options: ["would be", "will be", "would have been", "was"],
        answer: 2,
        explanation: "Conditional Type 3"
    },
    {
        question: "If you ______ to meet the President, what would you say?",
        options: ["happen", "happened", "were", "had"],
        answer: 2,
        explanation: "Conditional Type 2"
    },
    {
        question: "I would have been happier ______ I stayed at home.",
        options: ["if", "had", "provided", "unless"],
        answer: 1,
        explanation: "Conditional Type 3"
    },
    {
        question: "The company will bankrupt unless the government ______.",
        options: ["intervene", "intervenes", "intervened", "will intervene"],
        answer: 1,
        explanation: "Conditional Type 1"
    },
    {
        question: "______ the decision mine, I would handle it differently.",
        options: ["Is", "Was", "Were", "Had"],
        answer: 2,
        explanation: "Conditional Type 2"
    }
];