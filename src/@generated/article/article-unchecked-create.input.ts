import { Field, InputType, Int } from '@nestjs/graphql';

import { CommentUncheckedCreateNestedManyWithoutArticleInput } from '../comment/comment-unchecked-create-nested-many-without-article.input';
import { TagUncheckedCreateNestedManyWithoutArticlesInput } from '../tag/tag-unchecked-create-nested-many-without-articles.input';
import { UserUncheckedCreateNestedManyWithoutFavoriteArticlesInput } from '../user/user-unchecked-create-nested-many-without-favorite-articles.input';

@InputType()
export class ArticleUncheckedCreateInput {
    @Field(() => String, { nullable: true })
    articleId?: string;

    @Field(() => String, { nullable: false })
    slug!: string;

    @Field(() => String, { nullable: false })
    title!: string;

    @Field(() => String, { nullable: false })
    description!: string;

    @Field(() => String, { nullable: false })
    body!: string;

    @Field(() => TagUncheckedCreateNestedManyWithoutArticlesInput, { nullable: true })
    tags?: TagUncheckedCreateNestedManyWithoutArticlesInput;

    @Field(() => Date, { nullable: true })
    createdAt?: Date | string;

    @Field(() => Date, { nullable: true })
    updatedAt?: Date | string;

    @Field(() => Int, { nullable: true })
    favoritesCount?: number;

    @Field(() => String, { nullable: true })
    authorId?: string;

    @Field(() => UserUncheckedCreateNestedManyWithoutFavoriteArticlesInput, {
        nullable: true,
    })
    favoritedBy?: UserUncheckedCreateNestedManyWithoutFavoriteArticlesInput;

    @Field(() => CommentUncheckedCreateNestedManyWithoutArticleInput, {
        nullable: true,
    })
    comments?: CommentUncheckedCreateNestedManyWithoutArticleInput;
}
