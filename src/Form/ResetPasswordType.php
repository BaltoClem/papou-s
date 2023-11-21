<?php

namespace App\Form;

use App\Entity\User;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Validator\Constraints as Assert;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\RepeatedType;


class ResetPasswordType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $builder
        ->add('plainPassword', RepeatedType::class, [    // RepeatedType : Pour avoir un deuxième champ pour la confirmation du mdp (donc first_options et second_options)
            'type' => PasswordType::class,
            'first_options' => [
                'attr' => [
                    'class' => 'form-control',
                    'placeholder' => 'Veuillez entrer votre nouveau mot de passe',
                ],
                'label' => 'Nouveau mot de passe',
                'label_attr' => [
                    'class' => 'form-label mt-4'
                ],
                'constraints' => [
                    new Assert\NotBlank()
                ]
            ],
            'second_options' => [
                'attr' => [
                    'class' => 'form-control',
                    'placeholder' => 'Veuillez confirmer votre nouveau mot de passe',
                ],
                'label' => 'Confirmation du nouveau mot de passe',
                'label_attr' => [
                    'class' => 'form-label mt-4'
                ],
                'constraints' => [
                    new Assert\NotBlank()
                ]
            ],
            'invalid_message' => 'Les mots de passe ne correspondent pas'  // Message si les mdp 1 et 2 ne sont pas identiques
        ])

        ->add('submit', SubmitType::class, [
            'attr' => [
                'class' => 'btn btn-primary mt-4'
            ],
            'label' => 'Valider'
        ])
        ;
    }

    public function configureOptions(OptionsResolver $resolver)
    {
        $resolver->setDefaults([
            'data_class' => User::class,
        ]);
    }
}
