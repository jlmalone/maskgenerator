# This programme is for password guessing.
# It takes a file of initial word seeds.
# It takes a maximum number of capital letters in the initial word.
# It takes a maximum character number of Salting/Filler/Etraneous Numbers,UpperAlphas,LowerAlphas,$pecial Character.
# It takes a dictionary of potential keystroke errors, ie. one might hit 'w' accidentally instead of intended 'q'
# It takes a dictionary of unshifted to shifted characters
# It takes a set of potential $pecial Characters in the extraneous.
# It takes inputs for maximum Upper Characters of Original $eed
# It takes max number of keystroke errors
# It takes a minimum number of Numbers,UpperAlphas,LowerAlphas,$pecial Character for the final output
# It generates every permutation of extraneous character eg

# for a set of extraneous Characters containing 2 Uppers, One Number, and One $pecial:
# UU#$,U#U$,#UU$,UU$#,U$U#,$UU#,$#UU,#$UU,U$#U,U#$U
# for a set of extraneous Characters containing 1 Lower, One Upper, One Number, and One $pecial:
# UL#$,U#L$,#UL$,UL$#,U$L#,$UL#,$#UL,#$UL,U$#L,U#$L,LU#$,L#U$,#LU$,LU$#,L$U#,$LU#,$#LU,#$LU,L$#U,L#$U

# and so on. These extraneous character permutations (ECP) are combined.

# The original seed is expanded into word candidates by generating every combination of string
# containing uppercase letters up to the max allowed in the input (might be one or 2)

# Optional TODO: A reversal set with caps lock down is generated for each value. If a ranking system is implemented,
# these are placed at the lowest rank.

# The expanded seed list is then further expanded with Keystroke error possibilities.
# This operation will roughly expand the set by set by 7 * len(seed).
# It also includes a keystoke deletion and a doubletap

# eg pqssword, [assword, assword, ppassword, PPassword

# Optional TODO: add possibilities for extra insertion where the user had fat fingers eg:
# poassword, passeword, etc


# ECPs are then Tmesis combined (deck shuffled) with the characters from the seed.

# eg. PasswordUL#$, UPasswordL#$, ..., UPasLswo#rd$ ...

# Optional TODO. There may be an optional input added to rank masks based on liklihood. This will help
# in the case of resource constrains to prioritise likely candidates.

# Every seed word is combined with every other seed word including itself up to Three times.
# The maximum Upper for seeds is doubled (trebbled when self referential)
# This forms a new set of Seeds, and all the previous steps are repeated.

# The Placeholders for ECPs are replaced finally with custom charactersets and formatting and saved
# in an .hcmask file

# eg. #$%^&*,Password?u?l?d?1 where #$%^&* -> ?1 is the input special character set.

# if a mask is incapable of generating a password with the minimum set of required characters,
# it is eliminated

# The output file is intended to be run with hashcat to find a password solution to a particular hash or cipher
from Queue import Queue
import itertools
import os

KEYSTROKE_ERROR_MAP = {'`': ['1'], '1': ['`', '2', 'q'], '2': ['1', 'q', 'w', '3'], '4': ['3', 'e', 'r', '5'],
                       '3': ['2', 'w', 'e', '4'], '5': ['4', 'r', 't', '6'], '6': ['5', 't', 'y', '7'],
                       '7': ['6', 'y', 'u', '8'], '8': ['7', 'u', 'i', '9'], '9': ['8', 'i', 'o', '0'],
                       '0': ['9', 'o', 'p', '-'], '-': ['0', 'p', '[', '='], '=': ['-', '[', ']'],
                       'q': ['1', '2', 'w', 'a'], 'w': ['q', '2', '3', 'e', 's', 'a'],
                       'e': ['3', 'w', 's', 'd', 'r', '4'], 'r': ['4', 'e', 'd', 'f', 't', '5'],
                       't': ['r', '5', '6', 'y', 'g', 'f'], 'y': ['t', 'g', 'h', 'u', '7', '6'],
                       'u': ['7', 'y', 'h', 'j', 'i', '8'], 'i': ['u', 'j', 'k', 'o', '9', '8'],
                       'o': ['9', '0', 'p', 'l', 'k', 'i'],
                       'p': ['o', 'l', ';', '[', '-', '0'], '[': ['-', 'p', ';', '\'', ']', '='],
                       'a': ['q', 'w', 's', 'z'], 's': ['a', 'z', 'x', 'd', 'e', 'w'],
                       's': ['a', 'z', 'x', 'd', 'e', 'w'], 'd': ['e', 's', 'x', 'c', 'f', 'r'],
                       'f': ['d', 'c', 'v', 'g', 't', 'r'], 'g': ['f', 'v', 'b', 'h', 'y', 't'],
                       'h': ['g', 'b', 'n', 'j', 'u', 'y'], 'j': ['h', 'n', 'm', 'k', 'i', 'u'],
                       'k': ['j', 'm', ',', 'l', 'o', 'i'], 'l': ['k', ',', '.', ';', 'p', 'o'],
                       ';': ['l', '.', ';', 'p', 'o', '['], '\'': [';', '/', '[', ']'], 'z': ['a', 's', 'x'],
                       'x': ['z', 's', 'd', 'c'], 'c': ['x', 'd', 'f', 'v', ' '], 'v': ['c', 'f', 'g', 'b', ' '],
                       'b': ['v', 'g', 'h', 'n', ' '], 'n': ['b', 'h', 'j', 'm', ' '], ',': ['m', 'k', 'l', '.'],
                       '.': [',', 'l', ';', '/'], '/': ['.', ';', '\'']}

SHIFT_MAP = {'`': '~', '1': '!', '2': '@', '3': '#', '4': '$', '5': '%', '6': '^', '7': '&', '8': '*', '9': '(',
             '0': ')', '0': ')', '-': '_', '=': '+', 'q': 'Q', 'w': 'W', 'e': 'E', 'r': 'R', 't': 'T', 'y': 'Y',
             'u': 'U', 'i': 'I', 'o': 'O', 'p': 'P', '[': '{', ']': '}', '\\': '|', 'a': 'A', 's': 'S', 'd': 'D',
             'f': 'F', 'g': 'G', 'h': 'H', 'j': 'J', 'k': 'K', 'l': 'L', ';': ':', '\'': '"', 'z': 'Z', 'x': 'X',
             'c': 'C', 'v': 'V', 'b': 'B', 'n': 'N', 'm': 'M', ',': '<', '.': '>', '/': '?'}

UNSHIFT_MAP = dict([(v, k) for k, v in SHIFT_MAP.iteritems()])

CAP_LETTER = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z']
LOWER_LETTER = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v''w','x','y','z']
SPECIAL_CHARACTER_VARIANCE = '!~`#'
NUMBERS = '0123456789'

#there is an error here if ?u is involved
def containsLower(input):
    for l in LOWER_LETTER:
        if l in str(input):
            return True
    if '?l' in str(input):
        return True
    return False

def containsUpper(input):
    for u in CAP_LETTER:
        if u in str(input):
            return True
    if '?u' in str(input):
        return True
    return False

def containsSpecial(input):
    if '?1' in str(input):
        return True
    for s in SPECIAL_CHARACTER_VARIANCE:
        if s in input:
            return True
    return False
def containsNumber(input):
    cp = str(input).replace('?1','')
    if '?d' in cp:
        return True
    for n in NUMBERS:
        if n in cp:
            return True
    return False


def intToBinaryString(input):
    return "{0:b}".format(input)

def intToPrependedBinaryString(input, length):
    stringy = str(intToBinaryString(input))

    while length > len(stringy):
        stringy = '0'+stringy
    return stringy


def generateCombos(word, variin):
    lenword = len(word)
    MAXSTR = ''

    for c in word:
        MAXSTR = '1' + MAXSTR
        # print MAXSTR
    MINSTR = MAXSTR
    lenvariin = len(variin)
    for e in variin:
        MAXSTR = MAXSTR + '0'
        # print MAXSTR
    maxint = int(MAXSTR, 2)
    minint = int(MINSTR, 2)
    # print maxint
    # print minint

    sets = []
    binarystringset = []

    i = minint

    while i <= maxint:

        if bin(i).count("1") == lenword:
            strb = intToBinaryString(i)
            sets.append(i)
            # print i
            # print strb
        i = i + 1
    # print 'set lenght ' + str(len(sets))

    ret = []
    for s in sets:
        sstring = intToBinaryString(s)
        while len(sstring) < lenword + lenvariin:
            sstring = '0' + sstring
        binarystringset.append(sstring)
    for s in binarystringset:
        a = Queue()
        b = Queue()
        for c in word:
            a.put(c)
        for c in variin:
            b.put(c)
        finalString = ''
        for c in s:
            if c == '1':
                finalString = finalString + a.get()
            else:
                finalString = finalString + b.get()
        ret.append(finalString)
    return ret

# print 'Generate Combos \'wo\' \'rky\' \'hell\' \'o\''
# for w in generateCombos(['wo', 'rky', 'hell', 'o'], "ABCDEF"):
#     print w
# print 'FINISH'


def mistyper(input, upperlim):
    final = []
    index = 0
    final.append(input)
    while index < len(input):
        start = ''
        end = ''
        if(index>0):
            start = input[:index]
        if(index<len(input)-1):
            end = input[index+1:]
        ch = input[index]
        if KEYSTROKE_ERROR_MAP.has_key(ch):
            for b in KEYSTROKE_ERROR_MAP.get(ch):
                final.append(start+b+end)
                final.append(start+b+ch+end)
                final.append(start+ch+b+end)
            final.append(start+end)
            final.append(start+ch+ch+end)
        index = index+1
    return final



def capitalise(inputlist, maxCount):
    final = []
    for z in inputlist:
        lengthz = len(z)
        MAXINT = ''
        for c in z:
            MAXINT = MAXINT + '1'
        if MAXINT == '':
            continue
        maxint = int(MAXINT,2)
        # binarylenz = int(lengthz,2)
        t=0
        while t<=maxint:
            if bin(t).count('1')<=maxCount:
                addingstr = ''
                binstr = intToPrependedBinaryString(t,len(z))
                j=0
                for c in binstr:
                    if c=='0':
                        addingstr = addingstr+ z[j]

                    else:
                        if SHIFT_MAP.has_key(z[j]):
                            addingstr = addingstr + SHIFT_MAP.get(z[j])
                        else:
                            if UNSHIFT_MAP.has_key(z[j]):
                                addingstr = addingstr + UNSHIFT_MAP.get(z[j])
                            else:
                                addingstr = addingstr + z[j]

                    j=j+1
                final.append(str(addingstr))
            t=t+1
    return list(set(final))


def capslockon(inputlist, maxCount):
    final = []
    for z in inputlist:
        lengthz = len(z)
        MAXINT = ''
        for c in z:
            MAXINT = MAXINT + '1'
        maxint = int(MAXINT, 2)
        # binarylenz = int(lengthz,2)
        t = 0
        while t <= maxint:
            if bin(t).count('1') <= maxCount:
                addingstr = ''
                binstr = intToPrependedBinaryString(t, len(z))
                j = 0
                for c in binstr:
                    if c == '1':
                        addingstr = addingstr + z[j]

                    else:
                        if SHIFT_MAP.has_key(z[j]):
                            addingstr = addingstr + SHIFT_MAP.get(z[j])
                        else:
                            if UNSHIFT_MAP.has_key(z[j]):
                                addingstr = addingstr + UNSHIFT_MAP.get(z[j])
                            else:
                                addingstr = addingstr + z[j]

                    j = j + 1
                final.append(addingstr)
            t = t + 1
    return list(set(final))

# def capsLockCapitalise(inputlist, maxCount):



# print SHIFT_MAP.get('*')
# print 'MISTYPER hello 1'

# print 'print u'
# print 'length of u: '+str(len(z))
# for u in z:
#     print u
# print 'CAPITALISE'
# for c in capitalise(['goodbye'],2):
    # print c
# for d in capslockon(['goodbye'],2):
    # print d


# z = mistyper("goodbye", 1)
# fin = capitalise(z,2)+capslockon(z,2)
# fin = list(set(fin))

# for u in z:
#     print capitalise(str(u),2)



# print "COUNTING"+str(len(fin))
# for u in fin:
#     print u
# print "COUNTING"+str(len(fin))







#
#
# word = "worky"
# lenword = len(word)
# MAXSTR = ''
#
# for c in word:
#     MAXSTR = '1'+MAXSTR
#     # print MAXSTR
# MINSTR = MAXSTR
# variin = "ABCDEFGHIJK"
# lenvariin = len(variin)
# for e in variin:
#     MAXSTR = MAXSTR+'0'
#     # print MAXSTR
# maxint = int(MAXSTR,2)
# minint = int(MINSTR,2)
# print maxint
# print minint
#
# sets = []
# binarystringset = []
#
# i = minint
#
# while i<=maxint:
#
#     if bin(i).count("1") == lenword:
#         strb = intToBinaryString(i)
#         sets.append(i)
#         # print i
#         # print strb
#     i=i+1
# print 'set lenght '+str(len(sets))
#
# ret = []
# for s in sets:
#     sstring = intToBinaryString(s)
#     while len(sstring) < lenword + lenvariin:
#         sstring = '0'+sstring
#     binarystringset.append(sstring)
# for s in  binarystringset:
#     a = Queue()
#     b = Queue()
#     for c in word:
#         a.put(c)
#     for c in variin:
#         b.put(c)
#     finalString = ''
#     for c in s:
#         if c == '1':
#             finalString = finalString + a.get()
#         else:
#             finalString = finalString + b.get()
#     ret.append(finalString)


def openSeedParse():
    fina = []

    with open('seed.txt') as inputfile:
        for line in inputfile:
            splits = line.strip().split('_')
            print str(type(splits)) + 'type'
            fina.append(splits)
    return fina




def openSeedGetResults():

    results = []
    final = []
    with open('seed.txt') as inputfile:
        i = 0
        for line in inputfile:
            print type(line)
            results.append(line.strip().split(','))

            print line
            print 'hellp world'
            c = results[i]
            print 'c is ' + str(type(c))
            i = i + 1

    for s in results:
        print type(s)
        print str(s)
        print '\n'
        v = s

    for r in results:
        base = ''.join(r)
        # print str(base)
        for ind in range(len(base)):
            print base + ' ' + str(ind) + ' ' + base[ind]
            cha = base[ind]
            mistakes = [cha, '', cha + cha]
            mergedmistakes = []
            if KEYSTROKE_ERROR_MAP.has_key(cha):
                print 'HAS KEY: ' + cha
                print KEYSTROKE_ERROR_MAP[cha]

                mergedmistakes = KEYSTROKE_ERROR_MAP[cha]

            mergedmistakes = mergedmistakes + mistakes

            prefix = base[:ind]
            suffix = base[ind + 1:]
            possibilities = []

            for i in range(len(mergedmistakes)):
                possibilities.append((prefix + mergedmistakes[i] + suffix))

            final += possibilities


def makeVars(uppernum):
    out = []
    for i in range(1,3):#special
        line = []
        k = 1
        while k < i:
            line.append('?1')
            k = k+1

        for j in range(3-uppernum):
            line2 = list(line)
            m = 0
            while m < j:
                line2.append('?l')
                m=m+1
            for a in range(uppernum+1):
                line3 = list(line2)
                n = 0
                while n < a-1:
                    line3.append('?u')
                    n = n + 1
                for b in range(1,3):
                    line4 = list(line3)
                    p = 1
                    while p <b:
                        line4.append('?d')
                        p = p + 1
                    out.append(line4)
    return out


def makepermutatedvariables():
    lmt = makeVars(0) + makeVars(1) + makeVars(2)
    ls = []
    dic = {}
    for m in lmt:
        s = ''
        for n in m:
            s = s + n
        dic[s] = m

    for val in dic.values():
        ls.append(val)

    # setrlist = list(set(ls))


    # print 'permutated variables'
    out = []
    for ny in ls:
        permutedVariables = list(set(list(itertools.permutations(ny))))
        for x in permutedVariables:
            out.append(x)

    # print out

    dic = {}
    for m in out:
        s = ''
        for n in m:
            s = s + n
        dic[s] = m
    # print dic
    VARIABLES = []
    for val in dic.values():
        VARIABLES.append(val)
    return VARIABLES






# TODO
def domoretings():
    VARIABLES = makepermutatedvariables()

    # print VARIABLES

    # if not os.path.exists('~/hellpcombos.txt'):
    #     os.mknod('~/hellpcombos.txt')

    try:
        file = open('hellpcombos.txt', 'r')
    except IOError:
        file = open('hellpcombos.txt', 'w')

    # file = open('~/hellpcombos.txt','a+')
    for x in VARIABLES:
        for z in mistyper("hello",2):
            g = generateCombos(z,x)
            for u in g:
                file.write(SPECIAL_CHARACTER_VARIANCE + ',' + str(u) + '\n')
    file.close()



def saveToFile(list):
    # try:
    #     file = open('hellpcombos.txt', 'r')
    # except IOError:
    file = open('hellpcombos.hcmask', 'w')
    for u in list:
        file.write(SPECIAL_CHARACTER_VARIANCE + ',' + str(u) + '\n')
    file.close()




# d = list(set(list(itertools.permutations(y))))
# for v in d:
#     print v

def meetsExpectations(input):
    cpy = input
    if len(str(input).replace( '?', '')) <10:
        return False
    if containsUpper(input) and containsLower(input):
        if containsNumber(input):
            if containsSpecial(input):
                return True
    return False


def capitaliseParts(inputAr, maxCaps):
    lenar = []
    out = []
    for part in inputAr:
        lenar.append(len(part))
    stringy =  ''
    for part in inputAr:
        stringy = stringy + part
    strlist = [stringy]
    capsStringyAr = capitalise(strlist,maxCaps)

    for st in capsStringyAr:
        array = []
        i = 0
        for l in lenar:
            array.append(st[i:l+i])
            i = l+i
        out.append(array)
    return out



# pts = ['capi','talise','it']
# caps = capitaliseParts(pts,1)
# print caps

# print 'fina'
for f in openSeedParse():
    total = 0
    caps = capitaliseParts(f,1)
    out= []
    print f
    for v in makepermutatedvariables():
        for c in caps:
            g = generateCombos(c,v)
            for b in g:
                if meetsExpectations(b):
                    out.append(b)
    saveToFile(out)





#     capcobos = []
#     i = 0
#     val = []
#     while i < len(f):
#         j = 0
#         capslist = capitalise(f,1)
#
#         while j < len(f):
#             if i != j:
#                 val.append(f[])
#
#             j = j+1
#         i = i+1






    # for v in makepermutatedvariables():
    #     g = generateCombos(,v)
    #     for n in g:
    #         if meetsExpectations(n):
    #             print n
