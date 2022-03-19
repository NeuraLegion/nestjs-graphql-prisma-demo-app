import { Field, InputType } from '@nestjs/graphql';

import { ArticleUncheckedCreateNestedManyWithoutAuthorInput } from '../article/article-unchecked-create-nested-many-without-author.input';
import { ArticleUncheckedCreateNestedManyWithoutFavoritedByInput } from '../article/article-unchecked-create-nested-many-without-favorited-by.input';
import { CommentUncheckedCreateNestedManyWithoutAuthorInput } from '../comment/comment-unchecked-create-nested-many-without-author.input';
import { UserUncheckedCreateNestedManyWithoutFollowersInput } from './user-unchecked-create-nested-many-without-followers.input';

@InputType()
export class UserUncheckedCreateWithoutFollowersInput {
    @Field(() => String, { nullable: true })
    userId?: string;

    @Field(() => String, { nullable: false })
    email!: string;

    @Field(() => String, { nullable: false })
    name!: string;

    @Field(() => String, { nullable: false })
    password!: string;

    @Field(() => String, { nullable: true })
    bio?: string;

    @Field(() => String, { nullable: true })
    image?: string;

    @Field(() => UserUncheckedCreateNestedManyWithoutFollowersInput, { nullable: true })
    following?: UserUncheckedCreateNestedManyWithoutFollowersInput;

    @Field(() => ArticleUncheckedCreateNestedManyWithoutFavoritedByInput, {
        nullable: true,
    })
    favoriteArticles?: ArticleUncheckedCreateNestedManyWithoutFavoritedByInput;

    @Field(() => ArticleUncheckedCreateNestedManyWithoutAuthorInput, { nullable: true })
    articles?: ArticleUncheckedCreateNestedManyWithoutAuthorInput;

    @Field(() => CommentUncheckedCreateNestedManyWithoutAuthorInput, { nullable: true })
    comments?: CommentUncheckedCreateNestedManyWithoutAuthorInput;
}
