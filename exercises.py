"""
How to use this file:
  - Start the python terminal from the same directory where this file is hosted
  - import exercises
  - exercises.q1()          // asks a question
  - exercises.a1(answer)    // submits the answer 
"""
import random
import time

CORRECT = "Correct!"
WRONG = "Nope. Try again."

randos = []
count = 0
times = {}

def generate_randos():
    for x in range(100):
        randos.append(round(random.random() * 100))


def change_count():
    global count
    count = round(random.random() * 98)


def q1():
    print("Submit a string.")


def a1(answer):
    if type(answer) is str:
        print(CORRECT)
    else:
        print(WRONG)


def q2():
    print("What is the product (multiplication) of two numbers, (a, b)?")
    return randos[count], randos[count + 1]


def a2(answer):
    if answer == randos[count] * randos[count + 1]:
        print(CORRECT)
    else:
        print(WRONG)

    change_count()


def q3():
    print("What is floor of two numbers, (a, b)?")
    return randos[count], randos[count + 1]


def a3(answer):
    if answer == randos[count] // randos[count + 1]:
        print(CORRECT)
    else:
        print(WRONG)

    change_count()


def q4():
    print("What is the result of a number (a) to the power of another number (b) (exponents)?")
    return randos[count], randos[count + 1]


def a4(answer):
    if answer == randos[count] ** randos[count + 1]:
        print(CORRECT)
    else:
        print(WRONG)

    change_count()


def q5():
    print("What is the remainder of two numbers, (a, b)?")
    if randos[count] >= randos[count + 1]:
        return randos[count], randos[count + 1]
    else:
        return randos[count + 1], randos[count]


def a5(answer):
    correct_answer = 0
    if randos[count] >= randos[count + 1]:
        correct_answer = randos[count] % randos[count + 1]
    else:
        correct_answer = randos[count + 1] % randos[count]
    if answer == correct_answer:
        print(CORRECT)
    else:
        print(WRONG)

    change_count()


def q3():
    times['q3'] = time.time() * 1000
    print("What is the product (multiplication) of two numbers, (a, b)? You have 500ms")
    return randos[count], randos[count + 1]


def a3(answer):
    timelimit = times.get('q3') + 500
    current_time = time.time() * 1000
    correct_answer = randos[count] * randos[count + 1]
    if answer == correct_answer and current_time < timelimit:
        print(CORRECT)
    else:
        print(WRONG)

    change_count()


# initializes the random numbers and gets a random start point
generate_randos()
change_count()