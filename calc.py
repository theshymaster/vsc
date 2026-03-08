print("Calculator")
num1 = float(input("Enter your first number "))
operator = input("Enter your operation (*,/,+,-)")
num2 = float(input("Enter your second number "))

if operator == "+":
    result = num1 +num2
elif operator == "-":
    result = num1 - num2
elif operator == "*":
    result = num1 * num2 
elif operator == "/":
    result = num1 / num2 
    
else:
    result = "Invalid operator" 

print ("Result" , result)
