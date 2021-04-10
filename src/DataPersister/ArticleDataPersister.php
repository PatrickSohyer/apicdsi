<?php



// src/DataPersister



namespace App\DataPersister;



use App\Entity\Tag;
use App\Entity\Article;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\String\Slugger\SluggerInterface;
use ApiPlatform\Core\DataPersister\ContextAwareDataPersisterInterface;



class ArticleDataPersister implements ContextAwareDataPersisterInterface
{

    private $_entityManager;
    private $_slugger;
    private $_request;
    private $_security;

    public function __construct(
        EntityManagerInterface $entityManager,
        SluggerInterface $slugger,
        RequestStack $request,
        Security $security
    ){
        $this->_entityManager = $entityManager;
        $this->_slugger = $slugger;
        $this->_request = $request->getCurrentRequest();
        $this->_security = $security;
    }

    public function supports($data, array $context = []): bool
    {
        return $data instanceof Article;
    }

    public function persist($data, array $context = [])
    {
        $data->setSlug(
            $this->_slugger->slug(strtolower($data->getTitle()))
        );
        if($this->_request->getMethod() == 'POST'){
            $data->setAuthor($this->_security->getUser());
        }

        if($this->_request->getMethod() !== 'POST'){
            $data->setUpdatedAt(new \DateTime());
        }

        $tagRepository = $this->_entityManager->getRepository(Tag::class);
        foreach($data->getTags() as $tag){
            $tagInDb = $tagRepository->findOneByLabel($tag->getLabel());
            if($tagInDb !== null){
                $data->removeTag($tag);
                $data->addTag($tagInDb);
            }
        }

        $this->_entityManager->persist($data);
        $this->_entityManager->flush();
    }

    public function remove($data, array $context = [])
    {
        $this->_entityManager->remove($data);
        $this->_entityManager->flush();
    }
}