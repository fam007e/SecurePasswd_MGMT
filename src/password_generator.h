#ifndef PASSWORD_GENERATOR_H
#define PASSWORD_GENERATOR_H

double calculate_entropy(int length, int character_set_size);
void generate_password(int length, int use_case_variance, int use_numbers, int use_special);
char *generate_password_to_string(int length, int use_case_variance, int use_numbers, int use_special);

#endif // PASSWORD_GENERATOR_H